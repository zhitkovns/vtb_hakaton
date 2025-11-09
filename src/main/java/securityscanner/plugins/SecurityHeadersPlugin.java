package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class SecurityHeadersPlugin implements SecurityPlugin {
    @Override public String id() { return "API8:SecurityHeaders"; }
    @Override public String title() { return "Security Headers Check"; }
    @Override public String description() { return "Проверка наличия security заголовков"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        // Проверяем только безопасные эндпоинты
        String[] safeEndpoints = {"/", "/health", "/products"};
        
        Set<String> missingHeaders = new HashSet<>();
        Set<String> checkedEndpoints = new HashSet<>();
        
        for (String endpoint : safeEndpoints) {
            String url = ctx.baseUrl + endpoint;
            try (Response r = rex.get(url, headers)) {
                if (r.code() == 200) { // Проверяем только успешные ответы
                    checkSecurityHeaders(out, endpoint, r, missingHeaders, checkedEndpoints);
                }
            } catch (Exception e) {
                // Игнорируем недоступные эндпоинты
            }
        }

        return out;
    }

    private void checkSecurityHeaders(List<Finding> out, String endpoint, Response response, 
                                    Set<String> missingHeaders, Set<String> checkedEndpoints) {
        // Проверяем каждый эндпоинт только один раз
        if (checkedEndpoints.contains(endpoint)) {
            return;
        }
        checkedEndpoints.add(endpoint);

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
                String headerKeyShort = headerKey.replace("-", ""); // Для дедупликации
                if (!missingHeaders.contains(headerKeyShort)) {
                    missingHeaders.add(headerKeyShort);
                    out.add(Finding.of(endpoint, "GET", response.code(), id(),
                        header.getValue().severity,
                        header.getValue().message,
                        "",
                        "Добавьте security заголовок " + headerKey + " в ответы сервера"));
                }
            }
        }
    }

    private static class HeaderCheck {
        Finding.Severity severity;
        String message;
        
        HeaderCheck(Finding.Severity severity, String message) {
            this.severity = severity;
            this.message = message;
        }
    }
}