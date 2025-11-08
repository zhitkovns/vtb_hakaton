package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class SSRFPlugin implements SecurityPlugin {
    @Override public String id() { return "API7:2023-SSRF"; }
    @Override public String title() { return "Server Side Request Forgery"; }
    @Override public String description() { return "Проверка уязвимостей Server-Side Request Forgery"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Эндпоинты, которые могут быть уязвимы к SSRF
        String[] ssrfEndpoints = {
            "/webhooks",
            "/callbacks", 
            "/notifications",
            "/import",
            "/fetch"
        };

        // SSRF payloads для тестирования
        String[] ssrfPayloads = {
            "http://localhost:8080/admin",
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://internal.api.company/secret",
            "file:///etc/passwd",
            "http://[::1]:8080/private"
        };

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        for (String endpoint : ssrfEndpoints) {
            for (String payload : ssrfPayloads) {
                out.addAll(testSSRFVulnerability(ctx, rex, endpoint, payload, headers));
            }
        }

        return out;
    }

    private List<Finding> testSSRFVulnerability(ExecutionContext ctx, RequestExecutor rex,
                                              String endpoint, String payload, Map<String, String> headers) {
        List<Finding> out = new ArrayList<>();

        try {
            String url = ctx.baseUrl + endpoint;
            
            // Тестируем в query параметрах
            String testUrl = url + "?url=" + java.net.URLEncoder.encode(payload, "UTF-8");
            try (Response r = rex.get(testUrl, headers)) {
                analyzeSSRFResponse(out, endpoint, payload, r, "query parameter");
            }

            // Тестируем в теле запроса для POST endpoints
            if (endpoint.contains("webhook") || endpoint.contains("callback")) {
                String jsonBody = String.format("{\"url\": \"%s\", \"callback\": \"%s\"}", payload, payload);
                try (Response r = rex.postJson(url, jsonBody, headers)) {
                    analyzeSSRFResponse(out, endpoint, payload, r, "request body");
                }
            }

        } catch (Exception e) {
            // Ignore errors
        }

        return out;
    }

    private void analyzeSSRFResponse(List<Finding> out, String endpoint, String payload, 
                                   Response response, String vector) {
        int code = response.code();
        
        if (response.isSuccessful()) {
            out.add(Finding.of(endpoint, "GET/POST", code, id(),
                    Finding.Severity.HIGH,
                    "Возможная SSRF уязвимость: эндпоинт принял " + payload + " через " + vector,
                    ""));
        } else if (code == 400 || code == 422) {
            out.add(Finding.of(endpoint, "GET/POST", code, id(),
                    Finding.Severity.INFO,
                    "SSRF защита работает: эндпоинт отверг " + payload,
                    ""));
        }
    }
}