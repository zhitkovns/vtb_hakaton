package securityscanner.plugins;

import okhttp3.HttpUrl;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class BolaPlugin implements SecurityPlugin {
    @Override public String id() { return "API1:BOLA"; }
    @Override public String title() { return "Broken Object Level Authorization"; }
    @Override public String description() { return "Подмена client_id/чужие ресурсы → ожидать 403/404/401, иначе уязвимость."; }

@Override
public List<Finding> run(ExecutionContext ctx) throws Exception {
    List<Finding> out = new ArrayList<>();
    if (ctx.interbankClientId == null || ctx.interbankClientId.isBlank()) return out;

    // Увеличиваем задержку перед проверкой BOLA
    try { 
        Thread.sleep(2000); 
    } catch (InterruptedException e) { 
        Thread.currentThread().interrupt(); 
    }

    String other = "team999-1";
    HttpUrl.Builder ub = Objects.requireNonNull(HttpUrl.parse(ctx.baseUrl + "/accounts")).newBuilder();
    ub.addQueryParameter("client_id", other);
    String url = ub.build().toString();

    Map<String,String> h = new LinkedHashMap<>();
    if (ctx.accessToken != null) h.put("Authorization", "Bearer " + ctx.accessToken);
    if (ctx.requestingBank != null) h.put("X-Requesting-Bank", ctx.requestingBank);
    if (ctx.consentId != null) h.put("X-Consent-Id", ctx.consentId);

    RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);
    try (Response r = rex.get(url, h)) {
        int code = r.code();
        String body = r.body() != null ? r.body().string() : "";
        
        if (code == 429) {
            out.add(Finding.of("/accounts?client_id="+other, "GET", code, id(),
                    Finding.Severity.INFO, "Rate limiting prevented BOLA test - consider increasing delays", snippet(body)));
        } else if (code == 200) {
            out.add(Finding.of("/accounts?client_id="+other, "GET", code, id(),
                    Finding.Severity.HIGH, "CRITICAL: Broken Object Level Authorization - access to other user's data", snippet(body)));
        } else if (code == 403 || code == 404) {
            out.add(Finding.of("/accounts?client_id="+other, "GET", code, id(),
                    Finding.Severity.INFO, "BOLA protection working correctly", snippet(body)));
        } else {
            out.add(Finding.of("/accounts?client_id="+other, "GET", code, id(),
                    Finding.Severity.MEDIUM, "Unexpected response for BOLA test", snippet(body)));
        }
    }
    return out;
}

    private static String snippet(String s) {
        return s == null ? "" : (s.length()>800? s.substring(0,800)+"...(truncated)":s);
    }
}
