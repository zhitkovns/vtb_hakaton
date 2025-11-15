package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

/**
 * Плагин для проверки Broken Authentication - OWASP API2
 * Проверяет валидность токенов аутентификации и доступ к эндпоинтам без аутентификации
 */
public class AuthenticationPlugin implements SecurityPlugin {
    @Override public String id() { return "API2: BrokenAuth"; }
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

    /**
     * Проверяет валидность токена аутентификации через запрос к защищенным эндпоинтам
     */
    private void testTokenValidity(List<Finding> out, ExecutionContext ctx, RequestExecutor rex) {
        String[] testEndpoints = {"/accounts", "/cards", "/products"};
        
        for (String endpoint : testEndpoints) {
            String url = ctx.baseUrl + endpoint;
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + ctx.accessToken);
            if (ctx.requestingBank != null) {
                headers.put("X-Requesting-Bank", ctx.requestingBank);
            }
            
            try (Response r = rex.get(url, headers)) {
                if (r.code() == 401) {
                    // Токен невалиден - проблема
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.HIGH,
                            "Токен аутентификации невалиден или просрочен",
                            "Эндпоинт вернул 401 Unauthorized",
                            "Обновите токен аутентификации"));
                    return;
                } else if (r.code() == 403) {
                    // 403 - токен валиден, но нет прав
                    // Не добавляем как проблему - это ожидаемое поведение
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.INFO,
                            "Токен валиден, но требуется consent для доступа",
                            "Эндпоинт требует дополнительной авторизации",
                            ""));
                    return;
                } else if (r.isSuccessful()) {
                    // Токен работает
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                            Finding.Severity.INFO,
                            "Токен аутентификации валиден",
                            "Успешный доступ к защищенному эндпоинту",
                            ""));
                    return;
                }
            } catch (Exception e) {
                // Игнорируем ошибки подключения
            }
        }
    }

    /**
     * Проверяет возможность доступа к защищенным эндпоинтам без аутентификации
     */
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
                // Игнорируем ошибки подключения
            }
        }
    }
}