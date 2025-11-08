package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class SecurityMisconfigPlugin implements SecurityPlugin {
    @Override public String id() { return "API8:2023-SecurityMisconfig"; }
    @Override public String title() { return "Security Misconfiguration"; }
    @Override public String description() { return "Проверка типичных misconfiguration"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Проверка debug эндпоинтов
        String[] debugEndpoints = {"/debug", "/actuator", "/metrics", "/health", "/status", "/test"};
        
        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        for (String endpoint : debugEndpoints) {
            String url = ctx.baseUrl + endpoint;
            try (Response r = rex.get(url, headers)) {
                if (r.code() == 200) {
                    String body = r.body() != null ? r.body().string() : "";
                    // Проверяем, не содержит ли ответ чувствительной информации
                    if (body.contains("memory") || body.contains("heap") || 
                        body.contains("database") || body.contains("config")) {
                        out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.MEDIUM,
                            "Debug эндпоинт раскрывает системную информацию",
                            snippet(body)));
                    }
                }
            } catch (Exception e) {
                // Ignore connection errors
            }
        }

        // Проверка заголовков безопасности
        String mainUrl = ctx.baseUrl + "/accounts";
        try (Response r = rex.get(mainUrl, headers)) {
            checkSecurityHeaders(out, r, mainUrl);
        } catch (Exception e) {
            // Ignore if accounts endpoint is not accessible
        }

        return out;
    }

    private void checkSecurityHeaders(List<Finding> out, Response response, String endpoint) {
        Map<String, String> securityHeaders = Map.of(
            "Strict-Transport-Security", "HIGH",
            "X-Content-Type-Options", "MEDIUM", 
            "X-Frame-Options", "MEDIUM",
            "Content-Security-Policy", "MEDIUM"
        );

        for (Map.Entry<String, String> header : securityHeaders.entrySet()) {
            String value = response.header(header.getKey());
            if (value == null || value.isBlank()) {
                out.add(Finding.of(endpoint, "GET", response.code(), id(),
                    Finding.Severity.valueOf(header.getValue()),
                    "Отсутствует security заголовок: " + header.getKey(),
                    ""));
            }
        }
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 400 ? s.substring(0, 400) + "...(truncated)" : s);
    }
}