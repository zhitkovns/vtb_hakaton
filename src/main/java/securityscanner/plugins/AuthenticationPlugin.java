package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class AuthenticationPlugin implements SecurityPlugin {
    @Override public String id() { return "API2:2023-BrokenAuth"; }
    @Override public String title() { return "Broken Authentication"; }
    @Override public String description() { return "Проверка слабой аутентификации и авторизации"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Тест 1: Проверка валидности текущего токена
        if (ctx.accessToken != null) {
            testTokenValidity(out, ctx, rex);
        }

        // Тест 2: Попытка доступа без токена
        testAccessWithoutToken(out, ctx, rex);

        return out;
    }

    private void testTokenValidity(List<Finding> out, ExecutionContext ctx, RequestExecutor rex) {
        String[] testEndpoints = {"/accounts", "/cards", "/products"};
        
        for (String endpoint : testEndpoints) {
            String url = ctx.baseUrl + endpoint;
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + ctx.accessToken);
            
            try (Response r = rex.get(url, headers)) {
                if (r.code() == 401) {
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.HIGH,
                            "Токен аутентификации невалиден или просрочен",
                            "",
                            "Проверьте валидность токена, срок действия и права доступа"));
                    break; // Достаточно одной ошибки 401
                } else if (r.code() == 403) {
                    // 403 - токен валиден, но нет прав (нормально для некоторых эндпоинтов)
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.INFO,
                            "Токен валиден, но недостаточно прав доступа",
                            "",
                            "Создайте consent для доступа к защищенным эндпоинтам"));
                    break;
                } else if (r.isSuccessful()) {
                    // Токен работает
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.INFO,
                            "Токен аутентификации валиден",
                            "",
                            ""));
                    break;
                }
            } catch (Exception e) {
                // Ignore connection errors
            }
        }
    }

    private void testAccessWithoutToken(List<Finding> out, ExecutionContext ctx, RequestExecutor rex) {
        String[] sensitiveEndpoints = {"/accounts", "/cards", "/payments"};
        
        for (String endpoint : sensitiveEndpoints) {
            String url = ctx.baseUrl + endpoint;
            try (Response r = rex.get(url, Collections.emptyMap())) {
                if (r.code() == 200) {
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.HIGH,
                            "Эндпоинт доступен без аутентификации",
                            "",
                            "Требуйте аутентификацию для всех защищенных эндпоинтов"));
                } else if (r.code() == 401 || r.code() == 403) {
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.INFO,
                            "Эндпоинт правильно требует аутентификацию",
                            "",
                            ""));
                }
            } catch (Exception e) {
                // Ignore connection errors
            }
        }
    }
}