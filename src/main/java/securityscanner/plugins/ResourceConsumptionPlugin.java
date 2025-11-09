package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class ResourceConsumptionPlugin implements SecurityPlugin {
    @Override public String id() { return "API4:2023-ResourceConsumption"; }
    @Override public String title() { return "Unrestricted Resource Consumption"; }
    @Override public String description() { return "Проверка неограниченного потребления ресурсов (Rate Limiting)"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        
        // Тестируем только если у нас есть валидный доступ
        if (ctx.accessToken == null) {
            out.add(Finding.of("/accounts", "GET", 0, id(),
                    Finding.Severity.INFO, 
                    "Rate limiting test skipped - no valid access token", 
                    "",
                    "Получите валидный токен для тестирования rate limiting"));
            return out;
        }

        String url = ctx.baseUrl + "/accounts" + (ctx.interbankClientId!=null? "?client_id="+ctx.interbankClientId : "");
        Map<String,String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null && ctx.interbankClientId != null) headers.put("X-Requesting-Bank", ctx.requestingBank);
        if (ctx.consentId != null && ctx.interbankClientId != null) headers.put("X-Consent-Id", ctx.consentId);

        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);
        int requests = 5; // Уменьшаем количество запросов
        int successfulCalls = 0;
        int rateLimitedCalls = 0;

        for (int i = 0; i < requests; i++) {
            try {
                // Увеличиваем задержку между запросами
                if (i > 0) Thread.sleep(3000);
                
                try (Response r = rex.get(url, headers)) {
                    if (r.code() == 200) successfulCalls++;
                    if (r.code() == 429) rateLimitedCalls++;
                }
            } catch (Exception e) {
                // Ignore errors
            }
        }

        if (rateLimitedCalls > 0) {
            out.add(Finding.of("/accounts", "GET", 429, id(),
                    Finding.Severity.INFO, 
                    "Rate limiting активен: " + rateLimitedCalls + "/" + requests + " запросов ограничено", 
                    "successful: " + successfulCalls + ", rate limited: " + rateLimitedCalls,
                    "Настройте адаптивные задержки между запросами"));
        } else if (successfulCalls == requests) {
            out.add(Finding.of("/accounts", "GET", 200, id(),
                    Finding.Severity.LOW, 
                    "Rate limiting не обнаружен: все " + requests + " запросов успешны", 
                    "",
                    "Рассмотрите внедрение механизмов rate limiting для защиты от DoS атак"));
        } else {
            out.add(Finding.of("/accounts", "GET", 0, id(),
                    Finding.Severity.INFO, 
                    "Rate limiting тест: " + successfulCalls + "/" + requests + " успешных запросов", 
                    "",
                    ""));
        }
        return out;
    }
}