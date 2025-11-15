package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

/**
 * Плагин для проверки Security Misconfiguration - OWASP API8 
 * Проверяет типичные ошибки конфигурации безопасности включая security headers
 */
public class SecurityMisconfigPlugin implements SecurityPlugin {
    @Override public String id() { return "API8: SecurityMisconfig"; }
    @Override public String title() { return "Security Misconfiguration"; }
    @Override public String description() { return "Проверка типичных misconfiguration и security headers"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        // 1. Проверка security headers на основном эндпоинте (чтобы избежать дублирования)
        checkSecurityHeaders(out, ctx, rex, headers);

        // 2. Проверка debug эндпоинтов и интерфейсов управления
        checkDebugEndpoints(out, ctx, rex, headers);

        return out;
    }

    /**
     * Проверяет security headers на основном эндпоинте
     */
    private void checkSecurityHeaders(List<Finding> out, ExecutionContext ctx, RequestExecutor rex, Map<String, String> headers) throws Exception {
        // Проверяем только корневой эндпоинт чтобы избежать дублирования
        String url = ctx.baseUrl + "/";
        try (Response r = rex.get(url, headers)) {
            if (r.code() == 200) {
                checkSecurityHeadersInResponse(out, "/", r);
            }
        } catch (Exception e) {
            // Игнорируем недоступные эндпоинты
        }
    }

    /**
     * Проверяет security headers в ответе
     */
    private void checkSecurityHeadersInResponse(List<Finding> out, String endpoint, Response response) {
        Map<String, HeaderCheck> securityHeaders = new LinkedHashMap<>();
        securityHeaders.put("Strict-Transport-Security", new HeaderCheck(Finding.Severity.HIGH, "Отсутствует HSTS заголовок"));
        securityHeaders.put("X-Content-Type-Options", new HeaderCheck(Finding.Severity.MEDIUM, "Отсутствует X-Content-Type-Options"));
        securityHeaders.put("X-Frame-Options", new HeaderCheck(Finding.Severity.MEDIUM, "Отсутствует X-Frame-Options"));
        securityHeaders.put("Content-Security-Policy", new HeaderCheck(Finding.Severity.MEDIUM, "Отсутствует Content-Security-Policy"));
        securityHeaders.put("X-XSS-Protection", new HeaderCheck(Finding.Severity.LOW, "Отсутствует X-XSS-Protection"));

        for (Map.Entry<String, HeaderCheck> header : securityHeaders.entrySet()) {
            String value = response.header(header.getKey());
            if (value == null || value.isBlank()) {
                String headerKey = header.getKey();
                out.add(Finding.of(endpoint, "GET", response.code(), id(),
                    header.getValue().severity,
                    header.getValue().getMessage(),
                    "",
                    "Добавьте security заголовок " + headerKey + " в ответы сервера"));
            }
        }
    }

    /**
     * Проверяет debug эндпоинты и интерфейсы управления
     */
    private void checkDebugEndpoints(List<Finding> out, ExecutionContext ctx, RequestExecutor rex, Map<String, String> headers) throws Exception {
        String[] debugEndpoints = {"/debug", "/actuator", "/metrics", "/status", "/test"};
        
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
                // Игнорируем ошибки подключения
            }
        }
    }

    /**
     * Вспомогательный класс для хранения информации о проверяемом заголовке
     */
    private static class HeaderCheck {
        Finding.Severity severity;
        String message;
        
        HeaderCheck(Finding.Severity severity, String message) {
            this.severity = severity;
            this.message = message;
        }
        
        public String getMessage() {
            return message;
        }
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 400 ? s.substring(0, 400) + "...(truncated)" : s);
    }
}