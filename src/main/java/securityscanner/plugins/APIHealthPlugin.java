package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class APIHealthPlugin implements SecurityPlugin {
    @Override public String id() { return "API:Health"; }
    @Override public String title() { return "API Health Check"; }
    @Override public String description() { return "Проверка доступности и корректности основных эндпоинтов"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Только безопасные эндпоинты без проблем со схемой
        String[] safeEndpoints = {
            "/", 
            "/health",
            "/.well-known/jwks.json",
            "/products",
            "/info"
        };

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);

        for (String endpoint : safeEndpoints) {
            String url = ctx.baseUrl + endpoint;
            try (Response r = rex.get(url, headers)) {
                analyzeHealthResponse(out, endpoint, r);
            } catch (Exception e) {
                out.add(Finding.of(endpoint, "GET", 0, id(),
                        Finding.Severity.MEDIUM,
                        "Эндпоинт недоступен: " + e.getMessage(),
                        "",
                        "Проверьте доступность эндпоинта"));
            }
        }

        return out;
    }

    private void analyzeHealthResponse(List<Finding> out, String endpoint, Response response) {
        int code = response.code();
        
        if (code == 200) {
            out.add(Finding.of(endpoint, "GET", code, id(),
                    Finding.Severity.INFO,
                    "Эндпоинт доступен и работает",
                    "",
                    ""));
        } else if (code == 401 || code == 403) {
            out.add(Finding.of(endpoint, "GET", code, id(),
                    Finding.Severity.INFO,
                    "Эндпоинт доступен, требует аутентификации",
                    "",
                    ""));
        } else if (code == 429) {
            out.add(Finding.of(endpoint, "GET", code, id(),
                    Finding.Severity.LOW,
                    "Эндпоинт доступен, но ограничивает запросы",
                    "",
                    "Увеличьте интервалы между запросами"));
        } else if (code >= 500) {
            out.add(Finding.of(endpoint, "GET", code, id(),
                    Finding.Severity.HIGH,
                    "Эндпоинт возвращает серверную ошибку",
                    "",
                    "Проверьте стабильность сервера"));
        }
    }
}