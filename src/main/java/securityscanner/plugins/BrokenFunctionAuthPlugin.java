package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class BrokenFunctionAuthPlugin implements SecurityPlugin {
    @Override public String id() { return "API5:2023-BrokenFunctionAuth"; }
    @Override public String title() { return "Broken Function Level Authorization"; }
    @Override public String description() { return "Проверка несанкционированного доступа к административным функциям"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Эндпоинты, которые должны быть доступны только администраторам
        String[] adminEndpoints = {
            "/admin/users",
            "/admin/accounts", 
            "/admin/transactions",
            "/system/health",
            "/debug",
            "/metrics"
        };

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null) headers.put("X-Requesting-Bank", ctx.requestingBank);

        for (String endpoint : adminEndpoints) {
            String url = ctx.baseUrl + endpoint;
            
            try (Response r = rex.get(url, headers)) {
                int code = r.code();
                String body = r.body() != null ? r.body().string() : "";
                
                if (code == 200 || code == 201) {
                    out.add(Finding.of(endpoint, "GET", code, id(),
                            Finding.Severity.HIGH,
                            "Административный эндпоинт доступен обычному пользователю",
                            snippet(body)));
                } else if (code == 403 || code == 401) {
                    out.add(Finding.of(endpoint, "GET", code, id(),
                            Finding.Severity.INFO,
                            "Административный эндпоинт правильно защищен",
                            snippet(body)));
                }
            } catch (Exception e) {
                // Игнорируем ошибки подключения
            }
        }

        return out;
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 500 ? s.substring(0, 500) + "...(truncated)" : s);
    }
}