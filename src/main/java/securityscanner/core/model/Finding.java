package securityscanner.core.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Модель для представления найденной уязвимости или проблемы безопасности.
 * Содержит всю информацию о finding: эндпоинт, метод, статус, серьезность, рекомендации.
 */
public class Finding {
    public enum Severity { 
        @JsonProperty("info") INFO, 
        @JsonProperty("low") LOW, 
        @JsonProperty("medium") MEDIUM, 
        @JsonProperty("high") HIGH 
    }

    @JsonProperty("endpoint")
    public String endpoint;      // Эндпоинт API где найдена проблема
    
    @JsonProperty("method")  
    public String method;        // HTTP метод (GET, POST, PUT, DELETE)
    
    @JsonProperty("status")
    public int status;           // HTTP статус код ответа
    
    @JsonProperty("owasp")
    public String owasp;         // OWASP категория (например "API1:BOLA")
    
    @JsonProperty("severity")
    public Severity severity;    // Уровень серьезности проблемы
    
    @JsonProperty("message")
    public String message;       // Описание проблемы
    
    @JsonProperty("evidence")
    public String evidence;      // Доказательства (кусок ответа, заголовки)
    
    @JsonProperty("recommendation")
    public String recommendation; // Рекомендации по исправлению

    public Finding() {}

    /**
     * Создает finding с рекомендацией по умолчанию
     */
    public static Finding of(String endpoint, String method, int status,
                             String owasp, Severity sev, String msg, String ev) {
        return of(endpoint, method, status, owasp, sev, msg, ev, "");
    }

    /**
     * Создает finding с полной информацией
     */
    public static Finding of(String endpoint, String method, int status,
                             String owasp, Severity sev, String msg, String ev, String recommendation) {
        Finding f = new Finding();
        f.endpoint = endpoint;
        f.method = method;
        f.status = status;
        f.owasp = owasp;
        f.severity = sev;
        f.message = msg;
        f.evidence = ev;
        f.recommendation = recommendation;
        return f;
    }
}