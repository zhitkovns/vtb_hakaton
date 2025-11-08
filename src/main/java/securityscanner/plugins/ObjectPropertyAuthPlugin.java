package securityscanner.plugins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class ObjectPropertyAuthPlugin implements SecurityPlugin {
    private final ObjectMapper om = new ObjectMapper();
    
    @Override public String id() { return "API3:2023-ObjectPropertyAuth"; }
    @Override public String title() { return "Broken Object Property Level Authorization"; }
    @Override public String description() { return "Объединяет Excessive Data Exposure и Mass Assignment - проверка авторизации на уровне свойств объектов"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // Тест 1: Excessive Data Exposure - проверка чувствительных данных в ответах
        out.addAll(testExcessiveDataExposure(ctx, rex));
        
        // Тест 2: Mass Assignment - попытка модификации read-only полей
        out.addAll(testMassAssignment(ctx, rex));

        return out;
    }

    private List<Finding> testExcessiveDataExposure(ExecutionContext ctx, RequestExecutor rex) {
        List<Finding> out = new ArrayList<>();
        
        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null) headers.put("X-Requesting-Bank", ctx.requestingBank);
        if (ctx.consentId != null) headers.put("X-Consent-Id", ctx.consentId);

        String url = ctx.baseUrl + "/accounts" + 
                    (ctx.interbankClientId != null ? "?client_id=" + ctx.interbankClientId : "");
        
        try (Response r = rex.get(url, headers)) {
            if (r.code() == 200) {
                String body = r.body() != null ? r.body().string() : "";
                analyzeForSensitiveData(out, body, "/accounts");
            }
        } catch (Exception e) {
            // Ignore
        }

        return out;
    }

    private List<Finding> testMassAssignment(ExecutionContext ctx, RequestExecutor rex) {
        List<Finding> out = new ArrayList<>();

        // Пытаемся изменить read-only поля в запросе на создание счета
        String url = ctx.baseUrl + "/accounts";
        ObjectNode body = om.createObjectNode();
        body.put("account_type", "checking");
        body.put("initial_balance", 100);
        
        // Потенциально read-only поля, которые сервер должен игнорировать
        body.put("status", "Enabled");         // Должен устанавливаться сервером
        body.put("account_id", "hacked-123");  // Должен генерироваться сервером
        body.put("created_at", "2023-01-01");  // Должен устанавливаться сервером

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null) headers.put("X-Requesting-Bank", ctx.requestingBank);

        try (Response r = rex.postJson(url, om.writeValueAsString(body), headers)) {
            int code = r.code();
            String resp = r.body() != null ? r.body().string() : "";
            
            if (code >= 200 && code < 300) {
                out.add(Finding.of("/accounts", "POST", code, id(),
                        Finding.Severity.HIGH, 
                        "Сервер принял read-only/запрещенные поля (Broken Object Property Level Authorization)", 
                        snippet(resp)));
            } else if (code == 400 || code == 422) {
                out.add(Finding.of("/accounts", "POST", code, id(),
                        Finding.Severity.INFO,
                        "Сервер корректно отверг недопустимые свойства объекта",
                        snippet(resp)));
            }
        } catch (Exception e) {
            // Ignore
        }

        return out;
    }

    private void analyzeForSensitiveData(List<Finding> out, String responseBody, String endpoint) {
        if (responseBody == null || responseBody.isBlank()) return;

        String[] sensitivePatterns = {
            "password", "secret", "token", "key", "pin", 
            "ssn", "private_key", "credit_card", "cvv"
        };

        String lowerBody = responseBody.toLowerCase();
        for (String pattern : sensitivePatterns) {
            if (lowerBody.contains(pattern)) {
                out.add(Finding.of(endpoint, "GET", 200, id(),
                        Finding.Severity.MEDIUM,
                        "Обнаружены потенциально чувствительные данные: " + pattern,
                        snippet(responseBody)));
                break;
            }
        }
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 500 ? s.substring(0, 500) + "...(truncated)" : s);
    }
}