package securityscanner.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.time.Duration;
import java.util.Locale;

public class OpenAPIParserSimple {

    private final OkHttpClient http = new OkHttpClient.Builder()
            .callTimeout(Duration.ofSeconds(20))
            .build();

    private JsonNode root; // кэш openapi

    public String extractFirstServerUrl(String openapiLocation) throws Exception {
        JsonNode r = load(openapiLocation);
        this.root = r;
        JsonNode servers = r.path("servers");
        if (servers.isArray() && servers.size() > 0) {
            JsonNode url = servers.get(0).path("url");
            if (url.isTextual()) return url.asText();
        }
        return null;
    }

    public JsonNode getOpenApiRoot(String openapiLocation) throws Exception {
        if (root != null) return root;
        root = load(openapiLocation);
        return root;
    }

    /**
     * Найти JSON Schema для ответа по path + status + contentType.
     * Возвращает поддерево "schema": {...}
     */
    public JsonNode resolveResponseSchema(String openapiLocation, String path, int status, String contentType) throws Exception {
        JsonNode r = getOpenApiRoot(openapiLocation);
        JsonNode paths = r.path("paths");
        if (paths.isMissingNode()) return null;

        JsonNode pathNode = paths.path(path);
        if (pathNode.isMissingNode()) return null;

        // мы дергаем только GET в текущем коде; можно расширить при желании
        JsonNode op = pathNode.path("get");
        if (op.isMissingNode()) op = pathNode.path("post");
        if (op.isMissingNode()) op = pathNode.path("put");
        if (op.isMissingNode()) op = pathNode.path("delete");
        if (op.isMissingNode()) return null;

        String statusKey = String.valueOf(status);
        JsonNode resp = op.path("responses").path(statusKey);
        if (resp.isMissingNode()) {
            // иногда схемы кладут под "default"
            resp = op.path("responses").path("default");
            if (resp.isMissingNode()) return null;
        }

        JsonNode content = resp.path("content");
        if (content.isMissingNode() || !content.isObject()) return null;

        // нормализуем contentType (application/json; charset=utf-8 → application/json)
        String ct = contentType != null ? contentType.toLowerCase(Locale.ROOT) : "application/json";
        if (ct.contains(";")) ct = ct.substring(0, ct.indexOf(';')).trim();

        JsonNode ctNode = content.path(ct);
        if (ctNode.isMissingNode()) {
            // попробуем application/json по умолчанию
            ctNode = content.path("application/json");
            if (ctNode.isMissingNode()) return null;
        }
        return ctNode.path("schema").isMissingNode() ? null : ctNode.path("schema");
    }

    private JsonNode load(String openapiLocation) throws Exception {
        String json;
        if (openapiLocation.startsWith("http://") || openapiLocation.startsWith("https://")) {
            Request req = new Request.Builder().url(openapiLocation).get().build();
            try (Response r = http.newCall(req).execute()) {
                if (!r.isSuccessful()) throw new IllegalStateException("OpenAPI fetch failed: " + r.code());
                json = r.body() != null ? r.body().string() : "";
            }
        } else if (openapiLocation.startsWith("file:/")) {
            java.net.URI uri = java.net.URI.create(openapiLocation);
            json = java.nio.file.Files.readString(java.nio.file.Path.of(uri));
        } else {
            json = java.nio.file.Files.readString(java.nio.file.Path.of(openapiLocation));
        }
        ObjectMapper om = new ObjectMapper();
        return om.readTree(json);
    }
    public JsonNode resolveResponseSchemaFromRoot(JsonNode r, String path, int status, String contentType) {
    if (r == null) return null;
    JsonNode paths = r.path("paths");
    if (paths.isMissingNode()) return null;

    JsonNode pathNode = paths.path(path);
    if (pathNode.isMissingNode()) return null;

    JsonNode op = pathNode.path("get");
    if (op.isMissingNode()) op = pathNode.path("post");
    if (op.isMissingNode()) op = pathNode.path("put");
    if (op.isMissingNode()) op = pathNode.path("delete");
    if (op.isMissingNode()) return null;

    String statusKey = String.valueOf(status);
    JsonNode resp = op.path("responses").path(statusKey);
    if (resp.isMissingNode()) resp = op.path("responses").path("default");
    if (resp.isMissingNode()) return null;

    JsonNode content = resp.path("content");
    if (!content.isObject()) return null;

    String ct = (contentType == null ? "application/json" : contentType.toLowerCase(Locale.ROOT));
    if (ct.contains(";")) ct = ct.substring(0, ct.indexOf(';')).trim();

    JsonNode ctNode = content.path(ct);
    if (ctNode.isMissingNode()) ctNode = content.path("application/json");
    if (ctNode.isMissingNode()) return null;

    JsonNode schema = ctNode.path("schema");
    return schema.isMissingNode() ? null : schema;
}
}
