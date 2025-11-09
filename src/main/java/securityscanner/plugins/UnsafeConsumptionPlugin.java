package securityscanner.plugins;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class UnsafeConsumptionPlugin implements SecurityPlugin {
    private final ObjectMapper om = new ObjectMapper();
    
    @Override public String id() { return "API10:UnsafeConsumption"; }
    @Override public String title() { return "Unsafe Consumption of APIs"; }
    @Override public String description() { return "Проверка небезопасного взаимодействия с внешними API"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Проверка внешних ссылок и редиректов
        String[] externalCheckEndpoints = {
            "/payments/external",
            "/webhooks",
            "/callbacks",
            "/redirect"
        };

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        for (String endpoint : externalCheckEndpoints) {
            String url = ctx.baseUrl + endpoint;
            
            try (Response r = rex.get(url, headers)) {
                int code = r.code();
                
                // Проверка редиректов на внешние домены
                if (code >= 300 && code < 400) {
                    String location = r.header("Location");
                    if (location != null && isExternalUrl(location, ctx.baseUrl)) {
                        out.add(Finding.of(endpoint, "GET", code, id(),
                                Finding.Severity.MEDIUM,
                                "Редирект на внешний домен: " + location,
                                ""));
                    }
                }
                
                // Проверка внешних ссылок в теле ответа
                if (code == 200) {
                    String body = r.body() != null ? r.body().string() : "";
                    checkForExternalUrls(out, endpoint, body, ctx.baseUrl);
                }
            } catch (Exception e) {
                // Игнорируем недоступные эндпоинты
            }
        }

        // Проверка webhook/callback эндпоинтов на SSRF уязвимости
        checkSSRFVulnerabilities(out, ctx, rex);

        return out;
    }

    private void checkSSRFVulnerabilities(List<Finding> out, ExecutionContext ctx, RequestExecutor rex) {
        // Тест на потенциальные SSRF уязвимости через параметры URL
        String[] ssrfPayloads = {
            "http://localhost:8080/admin",
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        };

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        for (String payload : ssrfPayloads) {
            String testUrl = ctx.baseUrl + "/webhooks?url=" + java.net.URLEncoder.encode(payload);
            
            try (Response r = rex.get(testUrl, headers)) {
                if (r.isSuccessful()) {
                    out.add(Finding.of("/webhooks", "GET", r.code(), id(),
                            Finding.Severity.HIGH,
                            "Возможная SSRF уязвимость: эндпоинт принял URL " + payload,
                            ""));
                }
            } catch (Exception e) {
                // Игнорируем ошибки
            }
        }
    }

    private void checkForExternalUrls(List<Finding> out, String endpoint, String body, String baseUrl) {
        if (body == null || body.isBlank()) return;

        // Простая проверка на внешние URL в JSON ответе
        String[] externalIndicators = {"http://", "https://", "//"};
        
        for (String indicator : externalIndicators) {
            if (body.contains(indicator)) {
                // Извлекаем домен baseUrl для сравнения
                String baseDomain = extractDomain(baseUrl);
                if (baseDomain != null && !body.contains(baseDomain)) {
                    out.add(Finding.of(endpoint, "GET", 200, id(),
                            Finding.Severity.LOW,
                            "Обнаружены ссылки на внешние ресурсы в ответе",
                            snippet(body)));
                    break;
                }
            }
        }
    }

    private boolean isExternalUrl(String url, String baseUrl) {
        String urlDomain = extractDomain(url);
        String baseDomain = extractDomain(baseUrl);
        return urlDomain != null && baseDomain != null && !urlDomain.equals(baseDomain);
    }

    private String extractDomain(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String domain = uri.getHost();
            return domain != null ? domain.toLowerCase() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 300 ? s.substring(0, 300) + "...(truncated)" : s);
    }
}