package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class BrokenAuthPlugin implements SecurityPlugin {
    @Override public String id() { return "API2:2023-BrokenAuth"; }
    @Override public String title() { return "Broken Authentication"; }
    @Override public String description() { return "Проверка слабой аутентификации и авторизации"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);
        
        // Эндпоинты, которые должны требовать аутентификацию
        String[] sensitiveEndpoints = {"/accounts", "/balances", "/transactions", "/account-consents"};
        
        // Тест 1: Доступ без токена
        for (String endpoint : sensitiveEndpoints) {
            String url = ctx.baseUrl + endpoint;
            Map<String, String> noAuthHeaders = new HashMap<>();
            
            // Добавляем только технические заголовки без Authorization
            if (ctx.requestingBank != null) noAuthHeaders.put("X-Requesting-Bank", ctx.requestingBank);
            if (ctx.consentId != null) noAuthHeaders.put("X-Consent-Id", ctx.consentId);
            
            try (Response r = rex.get(url, noAuthHeaders)) {
                if (r.code() == 200) {
                    out.add(Finding.of(endpoint, "GET", r.code(), id(),
                        Finding.Severity.HIGH, 
                        "Эндпоинт доступен без аутентификации", 
                        ""));
                }
            } catch (Exception e) {
                // Ignore connection errors
            }
        }

        // Тест 2: Невалидный токен
        Map<String, String> invalidTokenHeaders = new HashMap<>();
        invalidTokenHeaders.put("Authorization", "Bearer invalid_token_12345");
        if (ctx.requestingBank != null) invalidTokenHeaders.put("X-Requesting-Bank", ctx.requestingBank);
        
        try (Response r = rex.get(ctx.baseUrl + "/accounts", invalidTokenHeaders)) {
            if (r.code() == 200) {
                out.add(Finding.of("/accounts", "GET", r.code(), id(),
                    Finding.Severity.HIGH,
                    "Эндпоинт доступен с невалидным токеном",
                    ""));
            } else if (r.code() != 401 && r.code() != 403) {
                out.add(Finding.of("/accounts", "GET", r.code(), id(),
                    Finding.Severity.MEDIUM,
                    "Нестандартный ответ на невалидный токен: " + r.code(),
                    ""));
            }
        } catch (Exception e) {
            // Ignore connection errors
        }

        return out;
    }
}