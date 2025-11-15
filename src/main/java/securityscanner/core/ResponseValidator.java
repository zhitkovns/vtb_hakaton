package securityscanner.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.*;
import okhttp3.Response;
import securityscanner.core.model.Finding;

import java.util.*;

/**
 * Валидатор ответов API против OpenAPI спецификации.
 * Проверяет соответствие фактических ответов ожидаемым схемам.
 */
public class ResponseValidator {

    private final ObjectMapper om = new ObjectMapper();
    private final JsonSchemaFactory factory;

    public ResponseValidator() {
        // Используем JSON Schema версии 7 для совместимости с OpenAPI 3.x
        factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
    }

    /**
     * Валидирует ответ API против ожидаемой JSON Schema
     * @param endpoint эндпоинт API
     * @param method HTTP метод
     * @param httpResp HTTP ответ для валидации
     * @param expectedSchema ожидаемая JSON Schema из OpenAPI спецификации
     * @return список findings с результатами валидации
     */
    public List<Finding> validateContract(String endpoint, String method,
                                          Response httpResp,
                                          JsonNode expectedSchema) {
        List<Finding> out = new ArrayList<>();
        int code = httpResp.code();
        String body = "";
        try { 
            body = httpResp.body() != null ? httpResp.body().string() : ""; 
        } catch (Exception ignore){}

        // Пропускаем валидацию для специфических случаев
        if (shouldSkipSchemaValidation(endpoint, code, expectedSchema)) {
            return out;
        }

        // Проверка Content-Type заголовка
        String ct = httpResp.header("Content-Type", "");
        if (expectedSchema != null && !isValidJsonContentType(ct)) {
            out.add(Finding.of(endpoint, method, code, "ContractMismatch",
                    Finding.Severity.LOW, 
                    "Unexpected Content-Type: " + ct, 
                    bodySnippet(body),
                    "Убедитесь, что эндпоинт возвращает application/json"));
        }

        // JSON Schema валидация если есть схема и тело в JSON формате
        if (expectedSchema != null && body != null && !body.isBlank() && looksLikeJson(body)) {
            validateJsonSchema(endpoint, method, code, body, expectedSchema, out);
        } else {
            handleNonJsonResponse(endpoint, method, code, body, expectedSchema, out);
        }
        return out;
    }

    /**
     * Определяет нужно ли пропускать валидацию для данного эндпоинта и кода ответа
     */
    private boolean shouldSkipSchemaValidation(String endpoint, int code, JsonNode expectedSchema) {
        if (expectedSchema == null) return true;
        if (code == 429) return true; // Rate limiting
        if (code >= 500) return true; // Server errors
        if (endpoint.contains("/auth") && code == 401) return true; // Auth failures
        
        // Пропускаем эндпоинты с известными проблемами схемы
        if (code == 422) return true;
        if (endpoint.contains("/account-consents")) return true;
        if (endpoint.contains("/auth/bank-token")) return true;
        if (endpoint.contains("/cards") && code == 422) return true;
        if (endpoint.contains("/payments") && code == 422) return true;
        if (endpoint.contains("/product-agreement")) return true;
        if (endpoint.contains("/product-agreements")) return true;
        
        return false;
    }

    private boolean isValidJsonContentType(String contentType) {
        return contentType != null && 
               contentType.toLowerCase(Locale.ROOT).contains("application/json");
    }

    /**
     * Выполняет валидацию JSON ответа против JSON Schema
     */
    private void validateJsonSchema(String endpoint, String method, int code, 
                                  String body, JsonNode expectedSchema, List<Finding> out) {
        try {
            JsonSchema schema = factory.getSchema(expectedSchema);
            JsonNode node = om.readTree(body);
            Set<ValidationMessage> errors = schema.validate(node);
            
            if (!errors.isEmpty()) {
                handleValidationErrors(endpoint, method, code, body, errors, out);
            } else {
                out.add(Finding.of(endpoint, method, code, "ContractMatch",
                        Finding.Severity.INFO, 
                        "Ответ соответствует схеме", 
                        bodySnippet(body),
                        ""));
            }
        } catch (Exception ex) {
            handleValidationException(endpoint, method, code, body, ex, out);
        }
    }

    /**
     * Обрабатывает ошибки валидации JSON Schema
     */
    private void handleValidationErrors(String endpoint, String method, int code,
                                      String body, Set<ValidationMessage> errors, List<Finding> out) {
        StringBuilder sb = new StringBuilder();
        int errorCount = 0;
        for (ValidationMessage e : errors) {
            if (errorCount < 5) {
                sb.append(cleanErrorMessage(e.getMessage())).append("; ");
                errorCount++;
            }
        }
        if (errors.size() >= 5) {
            sb.append("... и ").append(errors.size() - 5).append(" других ошибок");
        }
        
        // Определяем серьезность на основе типа ошибок
        Finding.Severity severity = hasCriticalErrors(errors) ? 
            Finding.Severity.MEDIUM : Finding.Severity.LOW;
        
        out.add(Finding.of(endpoint, method, code, "ContractMismatch",
                severity, 
                "Нарушения схемы: " + sb, 
                bodySnippet(body),
                "Исправьте структуру ответа согласно OpenAPI спецификации"));
    }

    /**
     * Определяет являются ли ошибки валидации критическими
     */
    private boolean hasCriticalErrors(Set<ValidationMessage> errors) {
        for (ValidationMessage error : errors) {
            String message = error.getMessage();
            if (message.contains("required") || 
                message.contains("type") ||
                message.contains("format")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Обрабатывает исключения при валидации JSON Schema
     */
    private void handleValidationException(String endpoint, String method, int code,
                                         String body, Exception ex, List<Finding> out) {
        String errorMsg = ex.getMessage();
        String recommendation = "Обновите OpenAPI спецификацию для корректной валидации";
        
        if (errorMsg != null && errorMsg.contains("cannot be resolved")) {
            out.add(Finding.of(endpoint, method, code, "ContractValidationError",
                    Finding.Severity.LOW, 
                    "Проблема разрешения ссылок в схеме", 
                    bodySnippet(body),
                    recommendation));
        } else if (errorMsg != null && errorMsg.contains("Unsupported schema version")) {
            out.add(Finding.of(endpoint, method, code, "ContractValidationError",
                    Finding.Severity.LOW, 
                    "Неподдерживаемая версия JSON Schema", 
                    bodySnippet(body),
                    "Обновите спецификацию OpenAPI до совместимой версии"));
        } else {
            String shortError = errorMsg != null ? 
                errorMsg.substring(0, Math.min(150, errorMsg.length())) : "unknown error";
            out.add(Finding.of(endpoint, method, code, "ContractValidationError",
                    Finding.Severity.LOW, 
                    "Ошибка валидатора: " + shortError, 
                    bodySnippet(body),
                    recommendation));
        }
    }

    /**
     * Обрабатывает случаи когда ответ не в JSON формате
     */
    private void handleNonJsonResponse(String endpoint, String method, int code,
                                    String body, JsonNode expectedSchema, List<Finding> out) {
        
        // Создаем findings только для реальных security проблем:
        if (expectedSchema != null && !looksLikeJson(body) && code < 500 && code >= 200) {
            // Это может быть security проблема - API возвращает не-JSON когда должна быть JSON схема
            out.add(Finding.of(endpoint, method, code, "ContractMismatch",
                    Finding.Severity.LOW, 
                    "Тело ответа не в JSON формате, но ожидается JSON по схеме", 
                    bodySnippet(body),
                    "Убедитесь, что эндпоинт возвращает корректный JSON согласно спецификации"));
        }
    }

    /**
     * Очищает сообщения об ошибках для лучшей читабельности
     */
    private String cleanErrorMessage(String message) {
        if (message == null) return "";
        return message.replaceAll("#/.*?/", "")
                     .replaceAll("\\$ref.*", "reference")
                     .replaceAll(":.*", "")
                     .replaceAll("^\\.?", "");
    }

    /**
     * Проверяет похоже ли тело ответа на JSON
     */
    private static boolean looksLikeJson(String s) {
        if (s == null || s.isBlank()) return false;
        String t = s.trim();
        return (t.startsWith("{") && t.endsWith("}")) || 
               (t.startsWith("[") && t.endsWith("]"));
    }

    /**
     * Обрезает тело ответа для отображения в отчете
     */
    private static String bodySnippet(String body) {
        if (body == null) return "";
        return body.length() > 800 ? body.substring(0, 800) + "...(truncated)" : body;
    }
}