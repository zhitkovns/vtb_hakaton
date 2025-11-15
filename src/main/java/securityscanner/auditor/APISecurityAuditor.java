package securityscanner.auditor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import securityscanner.core.*;
import securityscanner.core.model.Finding;
import securityscanner.generator.ScenarioGenerator;
import securityscanner.parser.OpenAPIParser;
import securityscanner.report.ReportWriter;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * Главный класс аудитора безопасности API.
 * Координирует весь процесс сканирования: аутентификацию, выполнение сценариев, запуск плагинов.
 */
public class APISecurityAuditor {

    private final boolean verbose;
    private final ObjectMapper om = new ObjectMapper();
    private final OkHttpClient http = new OkHttpClient.Builder()
            .callTimeout(Duration.ofSeconds(30))
            .readTimeout(Duration.ofSeconds(30))
            .build();

    private final List<Finding> findings = new ArrayList<>();
    private final ResponseValidator validator = new ResponseValidator();
    private final ReportWriter reportWriter = new ReportWriter();

    // Конфигурационные параметры сканирования
    private String openapiLocation;
    private String baseUrl;
    private String authArg; // Формат: "bearer:XXXXX"
    private String clientId;
    private String clientSecret;
    private String requestingBank;
    private String interbankClientId; // client_id для межбанковских запросов
    private boolean createConsent;
    private List<String> extraHeaders = List.of();

    // Механизм адаптивных задержек для избежания rate limiting
    private int lastStatusCode = 200;
    private int consecutive429s = 0;

    public APISecurityAuditor(boolean verbose) { this.verbose = verbose; }

    // Методы установки конфигурации
    public void setOpenapiLocation(String openapiLocation) { this.openapiLocation = openapiLocation; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    public void setAuthArg(String authArg) { this.authArg = authArg; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public void setRequestingBank(String requestingBank) { this.requestingBank = requestingBank; }
    public void setInterbankClientId(String interbankClientId) { this.interbankClientId = interbankClientId; }
    public void setCreateConsent(boolean createConsent) { this.createConsent = createConsent; }
    public void setExtraHeaders(List<String> extraHeaders) { this.extraHeaders = extraHeaders != null ? extraHeaders : List.of(); }

    private void log(String s) { if (verbose) System.out.println(s); }

    /**
     * Определяет базовый URL: из параметров или из OpenAPI спецификации
     */
    private String ensureBaseUrlFromOpenAPI(String current) throws Exception {
        if (current != null && !current.isBlank()) return current.replaceAll("/+$", "");
        if (openapiLocation == null || openapiLocation.isBlank()) return "";
        OpenAPIParser parser = new OpenAPIParser();
        String fromSpec = parser.extractFirstServerUrl(openapiLocation);
        if (fromSpec == null || fromSpec.isBlank()) return "";
        return fromSpec.replaceAll("/+$", "");
    }

    /**
     * Получает access token через несколько методов:
     * 1. Из аргумента --auth
     * 2. Из переменной окружения BANK_TOKEN
     * 3. Через client credentials flow
     */
    private String resolveAccessToken() throws Exception {
        String token = null;
        
        if (authArg != null && !authArg.isBlank()) {
            if (authArg.toLowerCase(Locale.ROOT).startsWith("bearer:")) {
                token = authArg.substring("bearer:".length()).trim();
                token = cleanToken(token);
                if (!token.isBlank()) {
                    System.out.println("Access token (from --auth) detected");
                    return token;
                }
            }
        }

        String env = System.getenv("BANK_TOKEN");
        if (env != null && !env.isBlank()) {
            token = cleanToken(env);
            System.out.println("Access token (from env BANK_TOKEN) detected");
            return token;
        }

        if (clientId != null && clientSecret != null && 
            !clientId.isBlank() && !clientSecret.isBlank()) {
            System.out.println("Attempting to fetch token using client credentials...");
            return fetchTokenWithClientCredentials();
        }

        throw new IllegalStateException(
            "No valid token found. Provide:\n" +
            "1. --auth 'bearer:YOUR_TOKEN' OR\n" +
            "2. BANK_TOKEN environment variable OR\n" + 
            "3. --client-id and --client-secret to fetch token automatically"
        );
    }

    /**
     * Получает токен через OAuth2 client credentials flow
     */
    private String fetchTokenWithClientCredentials() throws Exception {
        String url = baseUrl + "/auth/bank-token?client_id=" + encode(clientId) + 
                     "&client_secret=" + encode(clientSecret);
        Request req = new Request.Builder().url(url).post(RequestBody.create(new byte[0])).build();
        log("POST " + url);
        
        try (Response r = http.newCall(req).execute()) {
            String body = r.body() != null ? r.body().string() : "";
            System.out.println("Auth response status: " + r.code());
            
            if (!r.isSuccessful()) {
                findings.add(Finding.of("/auth/bank-token", "POST", r.code(), "AuthError",
                        Finding.Severity.HIGH, 
                        "Authentication failed: " + r.code(), 
                        body,
                        "Проверьте client_id и client_secret. Убедитесь, что они корректны и не истекли."));
                throw new IllegalStateException("Auth failed: " + r.code());
            }
            
            JsonNode node = om.readTree(body);
            String token = node.path("access_token").asText();
            if (token == null || token.isBlank()) {
                throw new IllegalStateException("Auth response has no access_token");
            }
            
            System.out.println("Access Token received successfully");
            return token;
        }
    }

    private String cleanToken(String token) {
        if (token == null) return null;
        return token.replaceAll("[\\r\\n\\t]", "").trim();
    }

    private static String encode(String v) { 
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8); 
    }

    private void applyExtraHeaders(Request.Builder b) {
        for (String h : extraHeaders) {
            int idx = h.indexOf(':');
            if (idx > 0) {
                String name = h.substring(0, idx).trim();
                String val = h.substring(idx + 1).trim();
                if (!name.isBlank() && !val.isBlank()) b.addHeader(name, val);
            }
        }
    }

    /**
     * Создает consent для доступа к защищенным данным, если требуется
     */
    private String createConsentIfNeeded(String token) throws Exception {
        if (!createConsent) {
            System.out.println("Consent creation skipped (--create-consent=false)");
            return null;
        }
        if (requestingBank == null || requestingBank.isBlank())
            throw new IllegalStateException("--create-consent requires --requesting-bank");
        if (interbankClientId == null || interbankClientId.isBlank())
            throw new IllegalStateException("--create-consent requires --client <client_id>");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", interbankClientId);
        body.put("permissions", Arrays.asList("ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail"));
        body.put("reason", "Security scanning and penetration testing");
        body.put("requesting_bank", requestingBank);
        body.put("requesting_bank_name", "Security Scanner Team " + requestingBank);
        body.put("valid_until", java.time.LocalDateTime.now().plusHours(1).format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        String json = om.writeValueAsString(body);
        String url = baseUrl + "/account-consents/request";
        Request.Builder rb = new Request.Builder()
                .url(url)
                .post(RequestBody.create(json, MediaType.parse("application/json")));
        rb.addHeader("Authorization", "Bearer " + token);
        rb.addHeader("X-Requesting-Bank", requestingBank);
        rb.addHeader("Content-Type", "application/json");
        applyExtraHeaders(rb);

        log("Creating consent for client: " + interbankClientId);
        log("POST " + url + " (create consent)");
        log("Body: " + json);
        
        try (Response r = http.newCall(rb.build()).execute()) {
            String resp = r.body() != null ? r.body().string() : "";
            System.out.println("Create consent status: " + r.code());
            log("Create consent response: " + resp);
            
            if (r.code() == 200 || r.code() == 201) {
                JsonNode node = om.readTree(resp);
                String consentId = extractConsentId(node);
                
                if (consentId != null && !consentId.isBlank()) {
                    System.out.println("Consent created successfully: " + consentId);
                    findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                            "ConsentManagement", Finding.Severity.INFO, 
                            "Consent created for security testing: " + consentId, 
                            "Client: " + interbankClientId,
                            "Убедитесь, что consent имеет ограниченное время жизни и необходимые разрешения"));
                    return consentId;
                } else {
                    System.out.println("Consent created but ID not found in response");
                    findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                            "ConsentManagement", Finding.Severity.MEDIUM,
                            "Consent created but no consent_id in response", resp,
                            "Исправьте формат ответа эндпоинта создания consent"));
                    return null;
                }
            } else if (r.code() == 403) {
                System.out.println("Consent creation failed: Permission denied (403)");
                findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                        "ConsentManagement", Finding.Severity.HIGH,
                        "Consent creation failed - insufficient permissions", resp,
                        "Проверьте права доступа и корректность токена аутентификации"));
                return null;
            } else if (r.code() == 401) {
                System.out.println("Consent creation failed: Unauthorized (401)");
                findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                        "ConsentManagement", Finding.Severity.HIGH,
                        "Consent creation failed - authentication required", resp,
                        "Убедитесь в валидности access token"));
                return null;
            } else {
                System.out.println("Consent creation failed with status: " + r.code());
                findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                        "ConsentManagement", Finding.Severity.MEDIUM,
                        "Consent creation failed with status: " + r.code(), resp,
                        "Проверьте корректность запроса и параметров consent"));
                return null;
            }
        }
    }

    private String extractConsentId(JsonNode node) {
        if (node.has("consent_id")) return node.get("consent_id").asText();
        if (node.has("data") && node.get("data").has("consentId")) 
            return node.get("data").get("consentId").asText();
        if (node.has("id")) return node.get("id").asText();
        return null;
    }

    /**
     * Ожидает подтверждения согласия пользователем
     */
    private boolean waitForConsentApproval(String token, String consentId) throws Exception {
        if (consentId == null || consentId.isBlank()) {
            return false;
        }

        System.out.println("\n=== ОЖИДАНИЕ ПОДТВЕРЖДЕНИЯ СОГЛАСИЯ ===");
        System.out.println("Создано согласие: " + consentId);
        System.out.println("Клиент: " + interbankClientId);
        System.out.println("Ожидание подтверждения пользователем...");
        System.out.println("Таймаут: 300 секунд");
        System.out.println("Для отмены нажмите Ctrl+C");

        int maxAttempts = 60; // 60 попыток * 5 секунд = 300 секунд
        int attempt = 0;

        while (attempt < maxAttempts) {
            attempt++;
            
            try {
                Thread.sleep(5000); // Проверяем каждые 5 секунд
            } catch (InterruptedException e) {
                System.out.println("Ожидание прервано пользователем");
                return false;
            }

            boolean isApproved = checkConsentStatus(token, consentId);
            if (isApproved) {
                return true;
            }

            if (attempt % 6 == 0) { // Каждые 30 секунд
                System.out.println("Ожидание... прошло " + (attempt * 5) + " секунд");
            }
        }

        System.out.println("Таймаут ожидания подтверждения согласия (300 секунд)");
        return false;
    }

    /**
     * Проверяет статус согласия с детальным анализом
     */
    private boolean checkConsentStatus(String token, String consentId) throws Exception {
        if (consentId == null || consentId.isBlank()) return false;
        
        String url = baseUrl + "/account-consents/" + consentId;
        Request.Builder rb = new Request.Builder().url(url).get();
        rb.addHeader("Authorization", "Bearer " + token);
        rb.addHeader("X-Requesting-Bank", requestingBank);
        applyExtraHeaders(rb);

        log("Checking consent status: " + consentId);
        
        try (Response r = http.newCall(rb.build()).execute()) {
            String resp = r.body() != null ? r.body().string() : "";
            log("Consent check response: " + resp);
            
            if (r.code() == 200) {
                JsonNode node = om.readTree(resp);
                
                // Пробуем разные пути к статусу
                String status = null;
                if (node.has("status")) {
                    status = node.path("status").asText();
                } else if (node.has("data") && node.get("data").has("status")) {
                    status = node.get("data").get("status").asText();
                }
                
                log("Consent status: " + status);
                
                if (status != null) {
                    if ("approved".equalsIgnoreCase(status) || 
                        "active".equalsIgnoreCase(status) ||
                        "authorized".equalsIgnoreCase(status)) {
                        return true;
                    } else if ("rejected".equalsIgnoreCase(status) || "denied".equalsIgnoreCase(status)) {
                        System.out.println("Согласие отклонено пользователем");
                        return false;
                    } else if ("expired".equalsIgnoreCase(status)) {
                        System.out.println("Согласие истекло");
                        return false;
                    } else if ("pending".equalsIgnoreCase(status)) {
                        System.out.println("Согласие ожидает подтверждения");
                        return false;
                    }
                }
                
                // Дополнительные проверки для автоматического одобрения
                if (node.has("auto_approved") && node.get("auto_approved").asBoolean()) {
                    System.out.println("Согласие автоматически одобрено");
                    return true;
                }
                
                System.out.println("Статус согласия не определен или не поддерживается: " + status);
                return false;
            } else if (r.code() == 404) {
                System.out.println("Согласие не найдено: " + consentId);
                return false;
            } else {
                System.out.println("Consent check failed with status: " + r.code());
                log("Response: " + resp);
                return false;
            }
        }
    }

    /**
     * Минимальная проверка токена - используется только если не удалось создать consent
     * чтобы определить: проблема в токене или в чем-то другом
     */
    private boolean checkTokenMinimalValidation(String token) throws Exception {
        if (token == null || token.isBlank()) {
            System.out.println("Token is null or empty");
            return false;
        }
        
        // Простая проверка на публичном эндпоинте который не требует consent
        String testUrl = baseUrl + "/products";
        Request.Builder rb = new Request.Builder().url(testUrl).get();
        rb.addHeader("Authorization", "Bearer " + token);
        applyExtraHeaders(rb);
        
        try (Response r = http.newCall(rb.build()).execute()) {
            int code = r.code();
            System.out.println("Minimal token check: " + testUrl + " -> " + code);
            
            // Только 401 = токен невалиден, все остальное = токен валиден
            // 403, 200, 404 - все это означает что токен валиден (сервер его принял)
            boolean isValid = code != 401;
            
            if (isValid) {
                System.out.println("Token is valid (received " + code + ")");
            } else {
                System.out.println("Token is INVALID (received 401)");
            }
            
            return isValid;
        } catch (Exception e) {
            System.out.println("Token check failed: " + e.getMessage());
            return false;
        }
    }

    private void validateAndRecord(String endpoint, String method, Response r, JsonNode expectedSchema) throws Exception {
        String body = r.body()!=null? r.body().string() : "";
        Response re = r.newBuilder()
                .body(ResponseBody.create(body, MediaType.parse(r.header("Content-Type", "application/json"))))
                .build();
        findings.addAll(validator.validateContract(endpoint, method, re, expectedSchema));
    }

    /**
     * Адаптивная система задержек для избежания rate limiting
     * Увеличивает задержки при получении 429 ошибок
     */
    private void adaptiveDelay() {
        try {
            long baseDelay = 2000;
            long delay;
            
            if (lastStatusCode == 429) {
                consecutive429s++;
                delay = baseDelay + (consecutive429s * 3000);
                System.out.println("Rate limit detected, increasing delay to " + delay + "ms");
                
                if (consecutive429s >= 3) {
                    System.out.println("Multiple rate limits, pausing for 30 seconds");
                    Thread.sleep(30000);
                    consecutive429s = 0;
                    return;
                }
            } else if (lastStatusCode >= 500) {
                delay = baseDelay + 2000;
                System.out.println("Server error, increasing delay to " + delay + "ms");
            } else {
                consecutive429s = 0;
                delay = baseDelay + new Random().nextInt(2000);
            }
            
            delay = Math.min(delay, 15000);
            Thread.sleep(delay);
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Sleep interrupted");
        }
    }

    /**
     * Выполняет один тестовый сценарий
     */
    private void runScenario(ScenarioGenerator.Scenario s, String token, String consentId, JsonNode openapiRoot, OpenAPIParser parser) throws Exception {
        adaptiveDelay();
        
        HttpUrl.Builder ub = Objects.requireNonNull(HttpUrl.parse(baseUrl + s.path)).newBuilder();
        s.query.forEach(ub::addQueryParameter);
        String url = ub.build().toString();

        Request.Builder rb = new Request.Builder().url(url);
        if (token != null && !token.isBlank()) rb.addHeader("Authorization", "Bearer " + token);
        s.headers.forEach(rb::addHeader);
        
        if (interbankClientId != null && s.query.containsKey("client_id")) {
            if (requestingBank != null && rb.build().header("X-Requesting-Bank") == null)
                rb.addHeader("X-Requesting-Bank", requestingBank);
            if (consentId != null && rb.build().header("X-Consent-Id") == null)
                rb.addHeader("X-Consent-Id", consentId);
        }
        applyExtraHeaders(rb);

        if ("POST".equals(s.method) || "PUT".equals(s.method)) {
            String json = s.body != null ? om.writeValueAsString(s.body) : "{}";
            rb.method(s.method, RequestBody.create(json, MediaType.parse("application/json")));
            log(s.method + " " + url + " Body:" + json);
        } else {
            rb.get();
            log(s.method + " " + url);
        }

        try (Response r = http.newCall(rb.build()).execute()) {
            int code = r.code();
            this.lastStatusCode = code;
            System.out.println(s.path + " ["+s.method+"/"+s.label+"] -> " + code);
            
            if (code == 403 && consentId == null && s.path.contains("/accounts")) {
                findings.add(Finding.of(s.path, s.method, code, "AccessControl",
                        Finding.Severity.INFO, 
                        "Expected 403 without consent", 
                        "",
                        "Эндпоинт правильно требует consent для доступа к данным"));
            }
            
            String ct = r.header("Content-Type","application/json");
            JsonNode schema = null;
            try {
                schema = parser.resolveResponseSchemaFromRoot(openapiRoot, s.path, r.code(), ct);
            } catch (Exception ignore) {
            }
            validateAndRecord(s.path, s.method, r, schema);
        } catch (Exception e) {
            System.err.println("ERROR executing scenario " + s.path + ": " + e.getMessage());
            findings.add(Finding.of(s.path, s.method, 0, "ExecutionError",
                    Finding.Severity.LOW, 
                    "Scenario execution failed: " + e.getMessage(), 
                    "",
                    "Проверьте доступность эндпоинта и корректность параметров запроса"));
        }
    }

    /**
     * Главный метод запуска сканирования
     */
    public void run() throws Exception {
        this.baseUrl = ensureBaseUrlFromOpenAPI(this.baseUrl);
        if (baseUrl == null || baseUrl.isBlank())
            throw new IllegalStateException("Base URL is empty. Provide --base-url or a spec with servers[].url");
        System.out.println("Resolved base-url: " + baseUrl);

        // Шаг 1: Получаем токен
        String token = resolveAccessToken();
        
        OpenAPIParser parser = new OpenAPIParser();
        JsonNode openapiRoot = parser.getOpenApiRoot(openapiLocation);

        // Шаг 2: Создаем consent - это обязательное требование
        System.out.println("Creating consent for client: " + interbankClientId);
        String consentId = createConsentIfNeeded(token);

        // Шаг 3: Проверяем результат создания consent
        if (consentId != null) {
            // Consent создался - токен точно валиден
            System.out.println("Token validation: PASSED (consent created successfully: " + consentId + ")");
            
            // Ожидаем подтверждения согласия пользователем
            boolean consentApproved = waitForConsentApproval(token, consentId);
            
            if (consentApproved) {
                System.out.println("Using active consent: " + consentId);
                // Запускаем полное сканирование с consent
                runSecurityScan(token, consentId, parser, openapiRoot);
                // Генерируем отчет после успешного сканирования
                generateReports(consentId);
            } else {
                System.out.println("Scanning aborted: consent not approved by user");
                findings.add(Finding.of("/account-consents", "N/A", 0, "ConsentManagement",
                        Finding.Severity.HIGH, 
                        "Scanning aborted - consent not approved", 
                        "",
                        "User must approve consent in personal account"));
                // Генерируем отчет о прерванном сканировании
                generateReports(null);
            }
        } else {
            // Consent не создался - сканирование невозможно
            System.out.println("Scanning aborted: cannot create consent");
            
            // Проверяем причину для диагностики
            boolean isTokenValid = checkTokenMinimalValidation(token);
            
            if (!isTokenValid) {
                findings.add(Finding.of("/auth", "N/A", 0, "AuthCheck",
                        Finding.Severity.HIGH, 
                        "Token validation failed - cannot create consent", 
                        "Token is invalid or expired",
                        "Check token validity and expiration"));
            } else {
                findings.add(Finding.of("/auth", "N/A", 0, "AuthCheck",
                        Finding.Severity.HIGH,
                        "Cannot create consent with valid token",
                        "Possible permissions issue or consent service problem",
                        "Check access permissions and consent service status"));
            }
            
            // Генерируем отчет о прерванном сканировании
            generateReports(null);
            return;
        }
    }

    /**
     * Выполняет основное сканирование безопасности
     */
    private void runSecurityScan(String token, String consentId, OpenAPIParser parser, JsonNode openapiRoot) throws Exception {
        try {
            ScenarioGenerator gen = new ScenarioGenerator();
            List<ScenarioGenerator.Scenario> scenarios = gen.generate(openapiRoot, requestingBank, interbankClientId);
            System.out.println("Generated " + scenarios.size() + " test scenarios");
            
            for (ScenarioGenerator.Scenario s : scenarios) {
                if ("DELETE".equals(s.method)) continue;
                try { 
                    runScenario(s, token, consentId, openapiRoot, parser); 
                } catch (Exception ex) {
                    findings.add(Finding.of(s.path, s.method, 0, "RunnerError",
                            Finding.Severity.LOW, 
                            "Scenario failed: " + ex.getMessage(), 
                            "",
                            "Проверьте корректность сценария тестирования"));
                }
            }

            PluginRegistry reg = new PluginRegistry().registerAll();
            ExecutionContext ctx = new ExecutionContext(
                    baseUrl, token, requestingBank, interbankClientId, consentId, verbose,
                    http, om, parser, openapiRoot, findings
            );

            System.out.println("Running " + reg.all().size() + " security plugins...");
            for (SecurityPlugin p : reg.all()) {
                try {
                    List<Finding> pf = p.run(ctx);
                    if (pf != null) findings.addAll(pf);
                    System.out.println(p.title() + " completed");
                } catch (Exception ex) {
                    findings.add(Finding.of("(plugin)", "N/A", 0, p.id(),
                            Finding.Severity.LOW, 
                            "Plugin error: " + ex.getMessage(), 
                            "",
                            "Проверьте корректность работы плагина безопасности"));
                    System.out.println(p.title() + " failed: " + ex.getMessage());
                }
            }

            probeCommonPaths(token, List.of("/health", "/", "/.well-known/jwks.json"), openapiRoot, parser);

        } catch (Exception e) {
            System.err.println("Security scan failed: " + e.getMessage());
            findings.add(Finding.of("(scanner)", "N/A", 0, "ScanError",
                    Finding.Severity.HIGH, 
                    "Security scan failed: " + e.getMessage(), 
                    "",
                    "Проверьте доступность API и корректность конфигурации"));
        }
    }

    /**
     * Генерирует финальные отчеты
     */
    private void generateReports(String consentId) throws Exception {
        System.out.println("Generating reports...");
        
        List<Finding> uniqueFindings = removeDuplicateFindings(findings);
        
        String bankName = extractBankNameFromUrl(baseUrl);
        String reportTitle = bankName + " API Security Report";

        var jsonFile = reportWriter.writeJson(reportTitle, openapiLocation, baseUrl, uniqueFindings);
        var pdfFile  = reportWriter.writePdf(reportTitle, openapiLocation, baseUrl, uniqueFindings);
        
        System.out.println("Total findings: " + findings.size());
        
        long highCount = findings.stream().filter(f -> f.severity == Finding.Severity.HIGH).count();
        long mediumCount = findings.stream().filter(f -> f.severity == Finding.Severity.MEDIUM).count();
        long lowCount = findings.stream().filter(f -> f.severity == Finding.Severity.LOW).count();
        long infoCount = findings.stream().filter(f -> f.severity == Finding.Severity.INFO).count();
        
        System.out.println("High: " + highCount + ", Medium: " + mediumCount + 
                          ", Low: " + lowCount + ", Info: " + infoCount);
        
        if (consentId != null) {
            System.out.println("Consent used: " + consentId);
        } else {
            System.out.println("No consent used - limited testing performed");
        }
        
        System.out.println("Reports:");
        System.out.println("  JSON: " + jsonFile.getAbsolutePath());
        System.out.println("  PDF : " + pdfFile.getAbsolutePath());
    }

    private void probeCommonPaths(String token, List<String> paths, JsonNode openapiRoot, OpenAPIParser parser) throws Exception {
        for (String p : paths) {
            adaptiveDelay();
            
            String url = baseUrl + p;
            Request.Builder rb = new Request.Builder().url(url).get();
            
            String cleanToken = cleanToken(token);
            if (cleanToken != null && !cleanToken.isBlank()) {
                rb.addHeader("Authorization", "Bearer " + cleanToken);
            }
            
            applyExtraHeaders(rb);
            log("GET " + url);
            
            try (Response r = http.newCall(rb.build()).execute()) {
                this.lastStatusCode = r.code();
                System.out.println(p + " -> " + r.code());
                String ct = r.header("Content-Type","application/json");
                JsonNode schema = null;
                try {
                    schema = parser.resolveResponseSchemaFromRoot(openapiRoot, p, r.code(), ct);
                } catch (Exception ignore) {}
                validateAndRecord(p, "GET", r, schema);
            } catch (Exception e) {
                System.err.println("ERROR probing " + p + ": " + e.getMessage());
                findings.add(Finding.of(p, "GET", 0, "ConnectionError",
                        Finding.Severity.LOW, 
                        "Failed to probe: " + e.getMessage(), 
                        "",
                        "Проверьте доступность эндпоинта и сетевое соединение"));
            }
        }
    }

    /**
     * Извлекает название банка из URL
     */
    private String extractBankNameFromUrl(String url) {
        if (url == null) return "Unknown Bank";
        if (url.contains("vbank")) return "Virtual Bank";
        if (url.contains("abank")) return "Awesome Bank";
        if (url.contains("sbank")) return "Smart Bank";
        return "Unknown Bank";
    }

    private List<Finding> removeDuplicateFindings(List<Finding> findings) {
        Map<String, Finding> uniqueMap = new LinkedHashMap<>();
        
        for (Finding finding : findings) {
            String key = createFindingKey(finding);
            
            // Для security headers объединяем по типу заголовка, а не по эндпоинту
            if (isSecurityHeaderFinding(finding)) {
                key = "security_header|" + extractHeaderName(finding.message);
            }
            
            // Сохраняем finding с максимальной severity или более конкретную информацию
            if (!uniqueMap.containsKey(key) || shouldReplaceFinding(uniqueMap.get(key), finding)) {
                uniqueMap.put(key, finding);
            }
        }
        
        return new ArrayList<>(uniqueMap.values());
    }

    private String createFindingKey(Finding finding) {
        // Для security headers используем специальный ключ
        if (isSecurityHeaderFinding(finding)) {
            return "security_header|" + extractHeaderName(finding.message);
        }
        
        // Для остальных findings обычный ключ
        return finding.endpoint + "|" + finding.method + "|" + finding.status + "|" + 
            finding.owasp + "|" + finding.message.substring(0, Math.min(40, finding.message.length()));
    }

    private boolean isSecurityHeaderFinding(Finding finding) {
        return finding.message != null && (
            finding.message.contains("X-Content-Type-Options") ||
            finding.message.contains("X-Frame-Options") ||
            finding.message.contains("X-XSS-Protection") ||
            finding.message.contains("Content-Security-Policy") ||
            finding.message.contains("Strict-Transport-Security")
        );
    }

    private String extractHeaderName(String message) {
        if (message.contains("X-Content-Type-Options")) return "X-Content-Type-Options";
        if (message.contains("X-Frame-Options")) return "X-Frame-Options";
        if (message.contains("X-XSS-Protection")) return "X-XSS-Protection";
        if (message.contains("Content-Security-Policy")) return "Content-Security-Policy";
        if (message.contains("Strict-Transport-Security")) return "Strict-Transport-Security";
        return message;
    }

    private boolean shouldReplaceFinding(Finding existing, Finding newFinding) {
        // Предпочитаем findings с evidence над findings без evidence
        if (existing.evidence.isEmpty() && !newFinding.evidence.isEmpty()) return true;
        // Предпочитаем более высокую severity
        if (newFinding.severity.ordinal() > existing.severity.ordinal()) return true;
        // Предпочитаем более короткие endpoint (основные а не конкретные)
        if (isSecurityHeaderFinding(newFinding) && newFinding.endpoint.length() < existing.endpoint.length()) return true;
        return false;
    }
}