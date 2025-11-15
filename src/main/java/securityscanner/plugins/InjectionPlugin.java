package securityscanner.plugins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

/**
 * Плагин для проверки инъекций - дополнительная проверка безопасности
 * Проверяет SQL, NoSQL и другие типы инъекций
 */
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

        Map<String, String> headers = new HashMap<>();
        if (ctx.accessToken != null) headers.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null) headers.put("X-Requesting-Bank", ctx.requestingBank);

        // Тестируем SQL инъекции в параметрах запроса
        for (String payload : sqlPayloads) {
            String url = ctx.baseUrl + "/accounts?client_id=" + payload;
            try (Response r = rex.get(url, headers)) {
                String body = r.body() != null ? r.body().string() : "";
                analyzeResponse(out, "/accounts", "GET", r.code(), payload, body, "SQL");
            }
        }

        // Тестируем NoSQL инъекции в теле запроса
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

    /**
     * Анализирует ответ на наличие признаков успешной инъекции
     */
    private void analyzeResponse(List<Finding> out, String endpoint, String method, 
                               int code, String payload, String body, String type) {
        
        // ИГНОРИРУЕМ нормальные бизнес-ответы - это НЕ инъекции
        if (isNormalBusinessResponse(code, body)) {
            return; // Не создаем finding для нормальных ответов
        }
        
        boolean isTruePositive = isTrueSqlInjection(code, body, payload, type);
        
        if (isTruePositive) {
            out.add(Finding.of(endpoint, method, code, id(),
                Finding.Severity.HIGH, 
                "Возможная " + type + " инъекция: " + payload, 
                snippet(body),
                "Используйте параметризованные запросы и строгую валидацию входных данных"));
        }
        // Убрана логика для MEDIUM severity при code=200 - это нормальное поведение
    }

    /**
     * Определяет, является ли ответ нормальным бизнес-ответом (не инъекцией)
     */
    private boolean isNormalBusinessResponse(int code, String body) {
        if (body == null || body.isEmpty()) return true;
        
        String lowerBody = body.toLowerCase();
        
        // Нормальные бизнес-ответы, которые НЕ являются инъекциями
        return (code == 403 && (lowerBody.contains("consent_required") || 
                               lowerBody.contains("insufficient_permissions") ||
                               lowerBody.contains("forbidden"))) ||
               (code == 401 && (lowerBody.contains("unauthorized") || 
                               lowerBody.contains("authentication_required"))) ||
               (code == 404 && (lowerBody.contains("not found") || 
                               lowerBody.contains("not_found"))) ||
               (code == 400 && (lowerBody.contains("validation error") || 
                               lowerBody.contains("bad_request"))) ||
               // Ответы с корректными данными - точно не инъекции
               (code == 200 && (lowerBody.contains("\"data\"") || 
                               lowerBody.contains("\"account\"") || 
                               lowerBody.contains("\"product\"") ||
                               lowerBody.contains("\"status\":\"ok\"")));
    }

    /**
     * Строгая проверка настоящих SQL инъекций
     */
    private boolean isTrueSqlInjection(int code, String body, String payload, String type) {
        // SQL инъекции обычно вызывают 500 ошибки или специфические ответы
        if (code != 500 && code != 200) return false;
        
        String lowerBody = body.toLowerCase();
        
        if (type.equals("SQL")) {
            // Специфические признаки SQL ошибок
            boolean hasSqlError = (lowerBody.contains("sql") && 
                   (lowerBody.contains("syntax") || 
                    lowerBody.contains("near \"") ||
                    lowerBody.contains("unknown column") ||
                    lowerBody.contains("you have an error in your sql"))) ||
                   (lowerBody.contains("postgresql") && lowerBody.contains("error")) ||
                   (lowerBody.contains("oracle") && lowerBody.contains("exception")) ||
                   (lowerBody.contains("mysql") && lowerBody.contains("error"));
            
            // Для 200 кодов - дополнительные проверки на успешную инъекцию
            if (code == 200) {
                return hasSqlError || 
                       (lowerBody.contains("union") && lowerBody.contains("select") && 
                        body.contains("1") && body.contains("2") && body.contains("3"));
            }
            
            return hasSqlError;
            
        } else if (type.equals("NoSQL")) {
            // Признаки NoSQL инъекций
            return lowerBody.contains("mongodb") && 
                   lowerBody.contains("error") &&
                   (lowerBody.contains("bson") || lowerBody.contains("unexpected"));
        }
        
        return false;
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 800 ? s.substring(0, 800) + "...(truncated)" : s);
    }
}