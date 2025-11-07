package securityscanner.generator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

public class ScenarioGenerator {

    private final ObjectMapper om = new ObjectMapper();

    public static class Scenario {
        public String path;
        public String method; // GET/POST/PUT/DELETE
        public Map<String,String> query = new LinkedHashMap<>();
        public Map<String,String> headers = new LinkedHashMap<>();
        public JsonNode body; // может быть null
        public String label;  // "positive" / "negative"

        public Scenario copy() {
            Scenario s = new Scenario();
            s.path = path;
            s.method = method;
            s.query = new LinkedHashMap<>(query);
            s.headers = new LinkedHashMap<>(headers);
            s.body = body;
            s.label = label;
            return s;
        }
    }

    public List<Scenario> generate(JsonNode openapiRoot, String requestingBank, String interbankClient) {
        List<Scenario> out = new ArrayList<>();
        JsonNode paths = openapiRoot.path("paths");
        if (!paths.isObject()) return out;

        Iterator<String> it = paths.fieldNames();
        while (it.hasNext()) {
            String p = it.next();
            JsonNode node = paths.path(p);

            for (String m : List.of("get","post","put","delete")) {
                JsonNode op = node.path(m);
                if (!op.isObject()) continue;

                Scenario s = new Scenario();
                s.path = p;
                s.method = m.toUpperCase(Locale.ROOT);
                s.label = "positive";
                // если это межбанковская зона /accounts и задан client_id — добавим query + заголовки
                if ("/accounts".equals(p) && interbankClient != null && !interbankClient.isBlank()) {
                    s.query.put("client_id", interbankClient);
                    if (requestingBank != null && !requestingBank.isBlank())
                        s.headers.put("X-Requesting-Bank", requestingBank);
                    // X-Consent-Id подставит раннер после создания согласия
                }
                // если есть requestBody со schema — положим минимальный валидный объект
                JsonNode reqBody = op.path("requestBody").path("content").path("application/json").path("schema");
                if (reqBody.isObject()) {
                    s.body = minimalValidJson(reqBody);
                }
                out.add(s);

                // Негатив (минимальный): убрать обязательный заголовок/параметр или испортить тип
                Scenario neg = s.copy();
                neg.label = "negative";
                if (neg.query.containsKey("client_id")) {
                    neg.query.put("client_id", "other-9999"); // ломаем контекст
                } else if (neg.body != null && neg.body.isObject()) {
                    // добавим поле не по схеме
                    ((com.fasterxml.jackson.databind.node.ObjectNode) neg.body).put("_unexpected", "boom");
                }
                out.add(neg);
            }
        }
        return out;
    }


    private JsonNode minimalValidJson(JsonNode schema) {
        var obj = om.createObjectNode();
        if (!schema.isObject()) return obj;
        if ("object".equals(schema.path("type").asText())) {
            JsonNode props = schema.path("properties");
            JsonNode req = schema.path("required");
            Set<String> required = new HashSet<>();
            if (req.isArray()) req.forEach(n -> required.add(n.asText()));
            if (props.isObject()) {
                Iterator<String> names = props.fieldNames();
                while (names.hasNext()) {
                    String name = names.next();
                    JsonNode ps = props.path(name);
                    if (required.isEmpty() || required.contains(name)) {
                        obj.set(name, defaultFor(ps));
                    }
                }
            }
            return obj;
        }
        return defaultFor(schema);
    }

    private JsonNode defaultFor(JsonNode s) {
        String t = s.path("type").asText();
        switch (t) {
            case "string":
                if (s.has("enum") && s.get("enum").isArray() && s.get("enum").size() > 0)
                    return s.get("enum").get(0);
                return new ObjectMapper().getNodeFactory().textNode("sample");
            case "integer":
            case "number":
                return new ObjectMapper().getNodeFactory().numberNode(1);
            case "boolean":
                return new ObjectMapper().getNodeFactory().booleanNode(true);
            case "array":
                var arr = new ObjectMapper().createArrayNode();
                JsonNode items = s.path("items");
                if (!items.isMissingNode()) arr.add(defaultFor(items));
                return arr;
            case "object":
                return minimalValidJson(s);
            default:
                return new ObjectMapper().getNodeFactory().textNode("sample");
        }
    }
}
