package securityscanner.auditor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import securityscanner.core.*;
import securityscanner.core.model.Finding;
import securityscanner.generator.ScenarioGenerator;
import securityscanner.parser.OpenAPIParserSimple;
import securityscanner.report.ReportWriter;

// плагины
import securityscanner.plugins.BolaPlugin;
import securityscanner.plugins.MassAssignmentPlugin;
import securityscanner.plugins.RateLimitPlugin;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

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

    private String openapiLocation;
    private String baseUrl;
    private String authArg; // "bearer:XXXX"
    private String clientId;
    private String clientSecret;
    private String requestingBank;
    private String interbankClientId;
    private boolean createConsent;
    private List<String> extraHeaders = List.of();

    public APISecurityAuditor(boolean verbose) { this.verbose = verbose; }

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

    private String ensureBaseUrlFromOpenAPI(String current) throws Exception {
        if (current != null && !current.isBlank()) return current.replaceAll("/+$", "");
        if (openapiLocation == null || openapiLocation.isBlank()) return "";
        OpenAPIParserSimple parser = new OpenAPIParserSimple();
        String fromSpec = parser.extractFirstServerUrl(openapiLocation);
        if (fromSpec == null || fromSpec.isBlank()) return "";
        return fromSpec.replaceAll("/+$", "");
    }

    private String resolveAccessToken() throws Exception {
        if (authArg != null && authArg.toLowerCase(Locale.ROOT).startsWith("bearer:")) {
            String t = authArg.substring("bearer:".length());
            System.out.println("Access token (from --auth) detected.");
            return t;
        }
        String env = System.getenv("BANK_TOKEN");
        if (env != null && !env.isBlank()) {
            System.out.println("Access token (from env BANK_TOKEN) detected.");
            return env;
        }
        if (clientId == null || clientSecret == null || clientId.isBlank() || clientSecret.isBlank())
            throw new IllegalStateException("No token and no CLIENT_ID/CLIENT_SECRET provided to fetch /auth/bank-token");

        String url = baseUrl + "/auth/bank-token?client_id=" + encode(clientId) + "&client_secret=" + encode(clientSecret);
        Request req = new Request.Builder().url(url).post(RequestBody.create(new byte[0])).build();
        log("POST " + url);
        try (Response r = http.newCall(req).execute()) {
            String body = r.body() != null ? r.body().string() : "";
            System.out.println("Auth response status: " + r.code());
            log("? Auth response body: " + body);
            if (!r.isSuccessful()) throw new IllegalStateException("Auth failed: " + r.code());
            JsonNode node = om.readTree(body);
            String token = node.path("access_token").asText();
            if (token == null || token.isBlank())
                throw new IllegalStateException("Auth response has no access_token");
            System.out.println("Access Token received: " + token.substring(0, Math.min(token.length(), 16)) + "...");
            return token;
        }
    }

    private static String encode(String v) { return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8); }

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

    private String createConsentIfNeeded(String token) throws Exception {
        if (!createConsent) return null;
        if (requestingBank == null || requestingBank.isBlank())
            throw new IllegalStateException("--create-consent requires --requesting-bank");
        if (interbankClientId == null || interbankClientId.isBlank())
            throw new IllegalStateException("--create-consent requires --client <client_id>");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", interbankClientId);
        body.put("permissions", List.of("ReadAccountsDetail", "ReadBalances"));
        body.put("reason", "HackAPI scan");
        body.put("requesting_bank", requestingBank);
        body.put("requesting_bank_name", "Team " + requestingBank);

        String json = om.writeValueAsString(body);
        String url = baseUrl + "/account-consents/request";
        Request.Builder rb = new Request.Builder()
                .url(url)
                .post(RequestBody.create(json, MediaType.parse("application/json")));
        rb.addHeader("Authorization", "Bearer " + token);
        rb.addHeader("X-Requesting-Bank", requestingBank);
        applyExtraHeaders(rb);

        log("POST " + url + " (create consent)");
        log("Body: " + json);
        try (Response r = http.newCall(rb.build()).execute()) {
            String resp = r.body() != null ? r.body().string() : "";
            System.out.println("Create consent status: " + r.code());
            log("Create consent response: " + resp);
            if (!r.isSuccessful()) throw new IllegalStateException("Create consent failed: " + r.code());
            JsonNode node = om.readTree(resp);
            String consentId = node.path("consent_id").asText();
            if (consentId == null || consentId.isBlank()) {
                JsonNode alt = node.path("data").path("consentId");
                consentId = alt.isMissingNode() ? null : alt.asText();
            }
            if (consentId == null || consentId.isBlank()) throw new IllegalStateException("No consent_id in response");
            System.out.println("Consent created: " + consentId);

            findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                    "ContractCheck", Finding.Severity.INFO, "Consent created: " + consentId, resp));
            return consentId;
        }
    }

    private void validateAndRecord(String endpoint, String method, Response r, JsonNode expectedSchema) throws Exception {
        // нужно прочитать тело до конца, а затем пересобрать response для валидатора
        String body = r.body()!=null? r.body().string() : "";
        Response re = r.newBuilder()
                .body(ResponseBody.create(body, MediaType.parse(r.header("Content-Type", "application/json"))))
                .build();
        findings.addAll(validator.validateContract(endpoint, method, re, expectedSchema));
    }

    private void runScenario(ScenarioGenerator.Scenario s, String token, String consentId, JsonNode openapiRoot, OpenAPIParserSimple parser) throws Exception {
    // URL
    HttpUrl.Builder ub = Objects.requireNonNull(HttpUrl.parse(baseUrl + s.path)).newBuilder();
    s.query.forEach(ub::addQueryParameter);
    String url = ub.build().toString();

    // Headers
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

    // Method/body
    if ("POST".equals(s.method) || "PUT".equals(s.method)) {
        String json = s.body != null ? om.writeValueAsString(s.body) : "{}";
        rb.method(s.method, RequestBody.create(json, MediaType.parse("application/json")));
        log(s.method + " " + url + " Body:" + json);
    } else {
        rb.get();
        log(s.method + " " + url);
    }

    try (Response r = http.newCall(rb.build()).execute()) {
        System.out.println(s.path + " ["+s.method+"/"+s.label+"] -> " + r.code());
        String ct = r.header("Content-Type","application/json");
        JsonNode schema = null;
        try {
            schema = parser.resolveResponseSchemaFromRoot(openapiRoot, s.path, r.code(), ct);
        } catch (Exception ignore) {
            // не валимся из-за схемы
        }
        validateAndRecord(s.path, s.method, r, schema);
    }
}

    public void run() throws Exception {
    this.baseUrl = ensureBaseUrlFromOpenAPI(this.baseUrl);
    if (baseUrl == null || baseUrl.isBlank())
        throw new IllegalStateException("Base URL is empty. Provide --base-url or a spec with servers[].url");
    System.out.println("Resolved base-url: " + baseUrl);

    String token = resolveAccessToken();

    OpenAPIParserSimple parser = new OpenAPIParserSimple();
    JsonNode openapiRoot = parser.getOpenApiRoot(openapiLocation);

    String consentId = null;
    if (createConsent) consentId = createConsentIfNeeded(token);

    try {
        // сценарии
        ScenarioGenerator gen = new ScenarioGenerator();
        List<ScenarioGenerator.Scenario> scenarios = gen.generate(openapiRoot, requestingBank, interbankClientId);
        for (ScenarioGenerator.Scenario s : scenarios) {
            if ("DELETE".equals(s.method)) continue;
            try { runScenario(s, token, consentId, openapiRoot, parser); }
            catch (Exception ex) {
                findings.add(Finding.of(s.path, s.method, 0, "RunnerError",
                        Finding.Severity.LOW, "Scenario failed: " + ex.getMessage(), ""));
            }
        }

        // плагины
        PluginRegistry reg = new PluginRegistry()
                .register(new securityscanner.plugins.BolaPlugin())
                .register(new securityscanner.plugins.MassAssignmentPlugin())
                .register(new securityscanner.plugins.RateLimitPlugin());

        ExecutionContext ctx = new ExecutionContext(
                baseUrl, token, requestingBank, interbankClientId, consentId, verbose,
                http, om, parser, openapiRoot, findings
        );

        for (SecurityPlugin p : reg.all()) {
            try {
                List<Finding> pf = p.run(ctx);
                if (pf != null) findings.addAll(pf);
            } catch (Exception ex) {
                findings.add(Finding.of("(plugin)", "N/A", 0, p.id(),
                        Finding.Severity.LOW, "Plugin error: " + ex.getMessage(), ""));
            }
        }

        // тех. пути
        probeCommonPaths(token, List.of("/health", "/", "/.well-known/jwks.json"), openapiRoot, parser);

    } finally {
        // ОТЧЁТЫ — пишем всегда
        var jsonFile = reportWriter.writeJson("Virtual Bank API Report", openapiLocation, baseUrl, findings);
        var pdfFile  = reportWriter.writePdf("Virtual Bank API Report", openapiLocation, baseUrl, findings);
        System.out.println("Reports:");
        System.out.println("  JSON: " + jsonFile.getAbsolutePath());
        System.out.println("  PDF : " + pdfFile.getAbsolutePath());
    }
}

    private void probeCommonPaths(String token, List<String> paths, JsonNode openapiRoot, OpenAPIParserSimple parser) throws Exception {
    for (String p : paths) {
        String url = baseUrl + p;
        Request.Builder rb = new Request.Builder().url(url).get();
        if (token != null && !token.isBlank()) rb.addHeader("Authorization", "Bearer " + token);
        applyExtraHeaders(rb);
        log("GET " + url);
        try (Response r = http.newCall(rb.build()).execute()) {
            System.out.println(p + " -> " + r.code());
            String ct = r.header("Content-Type","application/json");
            JsonNode schema = null;
            try {
                schema = parser.resolveResponseSchemaFromRoot(openapiRoot, p, r.code(), ct);
            } catch (Exception ignore) {}
            validateAndRecord(p, "GET", r, schema);
        }
    }
}
}
