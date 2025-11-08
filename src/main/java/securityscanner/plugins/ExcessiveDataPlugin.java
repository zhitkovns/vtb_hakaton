package securityscanner.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class ExcessiveDataPlugin implements SecurityPlugin {
    private final ObjectMapper om = new ObjectMapper();
    
    @Override public String id() { return "API3:ExcessiveData"; }
    @Override public String title() { return "Excessive Data Exposure"; }
    @Override public String description() { return "Проверка на раскрытие избыточных данных в ответах"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);

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
        }

        return out;
    }

    private void analyzeForSensitiveData(List<Finding> out, String responseBody, String endpoint) {
        if (responseBody == null || responseBody.isBlank()) return;

        try {
            JsonNode root = om.readTree(responseBody);
            checkForSensitiveFields(out, root, endpoint, "");
        } catch (Exception e) {
            // Если не JSON, проверяем как текст
            checkTextForSensitiveData(out, responseBody, endpoint);
        }
    }

    private void checkForSensitiveFields(List<Finding> out, JsonNode node, String endpoint, String path) {
        if (node.isObject()) {
            node.fieldNames().forEachRemaining(field -> {
                String currentPath = path.isEmpty() ? field : path + "." + field;
                JsonNode value = node.get(field);
                
                // Проверяем имя поля на чувствительные данные
                if (isSensitiveField(field)) {
                    out.add(Finding.of(endpoint, "GET", 200, id(),
                        Finding.Severity.MEDIUM,
                        "Обнаружено потенциально чувствительное поле: " + currentPath,
                        snippet(value.toString())));
                }
                
                // Рекурсивно проверяем вложенные объекты
                if (value.isObject() || value.isArray()) {
                    checkForSensitiveFields(out, value, endpoint, currentPath);
                }
            });
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                checkForSensitiveFields(out, node.get(i), endpoint, path + "[" + i + "]");
            }
        }
    }

    private void checkTextForSensitiveData(List<Finding> out, String text, String endpoint) {
        // Регулярные выражения для поиска чувствительных данных
        String[] patterns = {
            "password.*=.*[^\\s]+", "token.*=.*[^\\s]+", 
            "secret.*=.*[^\\s]+", "key.*=.*[^\\s]+"
        };
        
        for (String pattern : patterns) {
            if (text.toLowerCase().matches(".*" + pattern + ".*")) {
                out.add(Finding.of(endpoint, "GET", 200, id(),
                    Finding.Severity.MEDIUM,
                    "Обнаружены потенциально чувствительные данные в ответе",
                    snippet(text)));
                break;
            }
        }
    }

    private boolean isSensitiveField(String fieldName) {
        String lowerField = fieldName.toLowerCase();
        return lowerField.contains("password") || lowerField.contains("secret") ||
               lowerField.contains("token") || lowerField.contains("key") ||
               lowerField.contains("pin") || lowerField.contains("ssn") ||
               lowerField.contains("private") || lowerField.contains("internal");
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length() > 500 ? s.substring(0, 500) + "...(truncated)" : s);
    }
}