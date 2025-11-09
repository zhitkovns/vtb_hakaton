package securityscanner.core;

import securityscanner.core.model.Finding;

public abstract class BaseSecurityPlugin implements SecurityPlugin {
    
    protected Finding createFinding(String endpoint, String method, int status, 
                                  Finding.Severity severity, String message, String recommendation) {
        return Finding.of(endpoint, method, status, id(), severity, 
                         cleanMessage(message), "", cleanMessage(recommendation));
    }
    
    private String cleanMessage(String message) {
        if (message == null) return "";
        // Базовая очистка текста
        return message.replace("\n", " ")
                     .replace("\r", " ")
                     .replace("\t", " ")
                     .trim();
    }
}