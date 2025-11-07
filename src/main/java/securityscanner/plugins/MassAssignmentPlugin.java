package securityscanner.plugins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.Response;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;
import securityscanner.http.RequestExecutor;

import java.util.*;

public class MassAssignmentPlugin implements SecurityPlugin {
    private final ObjectMapper om = new ObjectMapper();

    @Override public String id() { return "API6:MassAssignment"; }
    @Override public String title() { return "Mass Assignment"; }
    @Override public String description() { return "Добавление запрещенных/readonly полей в POST/PUT тела."; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();

        // Пример: POST /accounts — добавим поля, которые сервер должен игнорировать/запретить
        String path = "/accounts";
        String url = ctx.baseUrl + path;
        ObjectNode body = om.createObjectNode();
        body.put("account_type", "checking");
        body.put("initial_balance", 100);

        // потенциально опасные поля, которые не должны приниматься клиентом
        body.put("status", "Enabled");         // readonly на стороне сервера
        body.put("nickname", "Hacked Account"); // сервер должен сам присваивать/валидировать

        Map<String,String> h = new LinkedHashMap<>();
        if (ctx.accessToken != null) h.put("Authorization", "Bearer " + ctx.accessToken);
        if (ctx.interbankClientId != null) h.put("X-Requesting-Bank", ctx.requestingBank);
        // Для bank_token нужен query client_id
        String urlWithQuery = url + (ctx.interbankClientId!=null? "?client_id="+ctx.interbankClientId : "");

        RequestExecutor rex = new RequestExecutor(ctx.http, ctx.verbose);
        try (Response r = rex.postJson(urlWithQuery, om.writeValueAsString(body), h)) {
            int code = r.code();
            String resp = r.body()!=null? r.body().string() : "";
            if (code >= 200 && code < 300) {
                out.add(Finding.of(path, "POST", code, id(),
                        Finding.Severity.HIGH, "Сервер принял тело с readonly/extra полями (Mass Assignment).", snippet(resp)));
            } else if (code == 400 || code == 422 || code == 403) {
                out.add(Finding.of(path, "POST", code, id(),
                        Finding.Severity.INFO, "Сервер корректно отверг лишние поля.", snippet(resp)));
            } else {
                out.add(Finding.of(path, "POST", code, id(),
                        Finding.Severity.LOW, "Неоднозначный ответ. Проверь поведение вручную.", snippet(resp)));
            }
        }
        return out;
    }

    private static String snippet(String s) {
        return s == null ? "" : (s.length()>800? s.substring(0,800)+"...(truncated)":s);
    }
}
