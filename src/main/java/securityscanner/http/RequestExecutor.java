package securityscanner.http;

import okhttp3.*;
import java.time.Duration;
import java.util.Map;

public class RequestExecutor {

    private final OkHttpClient http;
    private final boolean verbose;

    public RequestExecutor(OkHttpClient http, boolean verbose) {
        this.http = http.newBuilder()
                .callTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(30))
                .build();
        this.verbose = verbose;
    }

    public Response get(String url, Map<String, String> headers) throws Exception {
        Request.Builder rb = new Request.Builder().url(url).get();
        headers.forEach(rb::addHeader);
        if (verbose) System.out.println("GET " + url + " " + headers);
        return http.newCall(rb.build()).execute();
    }

    public Response postJson(String url, String json, Map<String, String> headers) throws Exception {
        RequestBody body = RequestBody.create(json, MediaType.parse("application/json"));
        Request.Builder rb = new Request.Builder().url(url).post(body);
        headers.forEach(rb::addHeader);
        if (verbose) {
            System.out.println("POST " + url + " " + headers);
            System.out.println("Body: " + (json.length() > 1000 ? json.substring(0, 1000) + "...(truncated)" : json));
        }
        return http.newCall(rb.build()).execute();
    }
}
