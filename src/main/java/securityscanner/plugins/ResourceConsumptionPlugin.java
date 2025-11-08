package securityscanner.plugins;

import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class ResourceConsumptionPlugin implements SecurityPlugin {
    @Override public String id() { return "API4:2023-ResourceConsumption"; }
    @Override public String title() { return "Unrestricted Resource Consumption"; }
    @Override public String description() { return "Проверка неограниченного потребления ресурсов (Rate Limiting)"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        String url = ctx.baseUrl + "/accounts" + (ctx.interbankClientId!=null? "?client_id="+ctx.interbankClientId : "");
        Map<String,String> h = new LinkedHashMap<>();
        if (ctx.accessToken != null) h.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.requestingBank != null && ctx.interbankClientId != null) h.put("X-Requesting-Bank", ctx.requestingBank);
        if (ctx.consentId != null && ctx.interbankClientId != null) h.put("X-Consent-Id", ctx.consentId);

        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);
        int n = 8, ok200=0, got429=0;
        String retryAfter = null;

        for (int i=0;i<n;i++) {
            try (Response r = rex.get(url, h)) {
                if (r.code()==200) ok200++;
                if (r.code()==429) {
                    got429++;
                    retryAfter = r.header("Retry-After");
                }
            }
        }
        if (got429>0) {
            out.add(Finding.of("/accounts", "GET", 429, id(),
                    Finding.Severity.INFO, "Сработало ограничение по частоте. Retry-After="+retryAfter, "burst="+n));
        } else {
            out.add(Finding.of("/accounts", "GET", 200, id(),
                    Finding.Severity.LOW, "Ограничение по частоте не проявилось на бурсте "+n+" запросов.", "ok200="+ok200));
        }
        return out;
    }
}