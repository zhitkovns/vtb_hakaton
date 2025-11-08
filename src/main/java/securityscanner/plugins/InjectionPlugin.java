package securityscanner.plugins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class InjectionPlugin implements SecurityPlugin {
    private final ObjectMapper om = new ObjectMapper();
    
    @Override public String id() { return "API8:Injection"; }
    @Override public String title() { return "SQL/NoSQL/Command Injection"; }
    @Override public String description() { return "Проверка на инъекции в параметрах запроса и теле"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

        // SQL инъекции в query параметрах
        String[] sqlPayloads = {"' OR '1'='1", "1; DROP TABLE users", "' UNION SELECT 1,2,3--", 
                               "1' AND 1=1 --", "1' OR '1'='1' --"};
        
        // NoSQL инъекции
        String[] nosqlPayloads = {"{\"$ne\": \"invalid\"}", "{\"$gt\": \"\"}", "{\"$where\": \"1==1\"}"};
        
        // Командные инъекции
        String[] commandPayloads = {"| whoami", "; ls -la", "`id`", "$(cat /etc/passwd)"};

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null) headers.put("X-Requesting-Bank", ctx.requestingBank);

        // Тестируем параметры запроса
        for (String payload : sqlPayloads) {
            String url = ctx.baseUrl + "/accounts?client_id=" + payload;
            try (Response r = rex.get(url, headers)) {
                String body = r.body() != null ? r.body().string() : "";
                analyzeResponse(out, "/accounts", "GET", r.code(), payload, body, "SQL");
            }
        }

        // Тестируем тело запроса для NoSQL инъекций
        for (String payload : nosqlPayloads) {
            String url = ctx.baseUrl + "/accounts";
            ObjectNode body = om.createObjectNode();
            body.put("client_id", payload);
            
            try (Response r = rex.postJson(url, om.writeValueAsString(body), headers)) {
                String responseBody = r.body() != null ? r.body().string() : "";
                analyzeResponse(out, "/accounts", "POST", r.code(), payload, responseBody, "NoSQL");
            }
        }

        return out;
    }

    private void analyzeResponse(List<Finding> out, String endpoint, String method, 
                               int code, String payload, String body, String type) {
        if (code == 500 || body.toLowerCase().contains("sql") || 
            body.toLowerCase().contains("syntax") || body.toLowerCase().contains("error") ||
            body.toLowerCase().contains("exception") || body.toLowerCase().contains("mongodb")) {
            
            out.add(Finding.of(endpoint, method, code, id(),
                Finding.Severity.HIGH, 
                "Возможная " + type + " инъекция: " + payload, 
                snippet(body)));
        } else if (code == 200) {
            out.add(Finding.of(endpoint, method, code, id(),
                Finding.Severity.MEDIUM,
                type + " инъекция не вызвала ошибку: " + payload,
                snippet(body)));
        }
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 800 ? s.substring(0, 800) + "...(truncated)" : s);
    }
}