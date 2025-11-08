package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class BusinessFlowPlugin implements SecurityPlugin {
    @Override public String id() { return "API6:2023-BusinessFlow"; }
    @Override public String title() { return "Unrestricted Access to Sensitive Business Flows"; }
    @Override public String description() { return "Проверка неограниченного доступа к чувствительным бизнес-процессам"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Бизнес-процессы, которые могут быть уязвимы для автоматизации
        String[] businessFlowEndpoints = {
            "/account-consents/request",  // Создание согласий
            "/payments",                  // Платежи
            "/transactions",              // Транзакции
            "/product-agreements"         // Создание договоров
        };

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null) headers.put("X-Requesting-Bank", ctx.requestingBank);

        // Тестируем возможность быстрого повторного вызова бизнес-процессов
        for (String endpoint : businessFlowEndpoints) {
            out.addAll(testBusinessFlowRate(ctx, rex, endpoint, headers));
        }

        return out;
    }

    private List<Finding> testBusinessFlowRate(ExecutionContext ctx, RequestExecutor rex, 
                                             String endpoint, Map<String, String> headers) {
        List<Finding> out = new ArrayList<>();
        
        String url = ctx.baseUrl + endpoint;
        int successfulCalls = 0;
        int totalCalls = 3; // Небольшое количество вызовов для теста

        for (int i = 0; i < totalCalls; i++) {
            try {
                // Добавляем задержку между вызовами
                if (i > 0) {
                    Thread.sleep(500);
                }

                Response r;
                if (endpoint.contains("consents") || endpoint.contains("agreements")) {
                    // Для POST endpoints отправляем минимальное тело
                    String jsonBody = "{\"reason\":\"Business flow test " + i + "\"}";
                    r = rex.postJson(url, jsonBody, headers);
                } else {
                    r = rex.get(url, headers);
                }

                if (r.isSuccessful()) {
                    successfulCalls++;
                }

                r.close();
            } catch (Exception e) {
                // Ignore errors
            }
        }

        // Если все вызовы успешны - возможна уязвимость
        if (successfulCalls == totalCalls) {
            out.add(Finding.of(endpoint, "MULTIPLE", 200, id(),
                    Finding.Severity.MEDIUM,
                    "Бизнес-процесс может быть подвержен автоматизации: " + successfulCalls + "/" + totalCalls + " успешных вызовов",
                    ""));
        } else if (successfulCalls > 0) {
            out.add(Finding.of(endpoint, "MULTIPLE", 200, id(),
                    Finding.Severity.LOW,
                    "Бизнес-процесс частично доступен для автоматизации: " + successfulCalls + "/" + totalCalls + " успешных вызовов",
                    ""));
        }

        return out;
    }
}