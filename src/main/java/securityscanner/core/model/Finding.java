package securityscanner.core.model;

public class Finding {
    public enum Severity { INFO, LOW, MEDIUM, HIGH }

    public String endpoint;
    public String method;
    public int status;
    public String owasp;       // например API1:BOLA, или "ContractMismatch"
    public Severity severity;
    public String message;
    public String evidence;    // кусок ответа/заголовков/trace
    public String recommendation; // Рекомендация по исправлению

    public Finding() {}

    public static Finding of(String endpoint, String method, int status,
                             String owasp, Severity sev, String msg, String ev) {
        return of(endpoint, method, status, owasp, sev, msg, ev, "");
    }

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