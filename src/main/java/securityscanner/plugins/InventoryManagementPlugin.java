package securityscanner.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;

import java.util.*;

public class InventoryManagementPlugin implements SecurityPlugin {
    @Override public String id() { return "API9:2023-InventoryManagement"; }
    @Override public String title() { return "Improper Inventory Management"; }
    @Override public String description() { return "Проверка устаревших версий API и документации"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();

        if (ctx.openapiRoot == null) {
            out.add(Finding.of("N/A", "N/A", 0, id(),
                    Finding.Severity.LOW, "OpenAPI спецификация не доступна для анализа", ""));
            return out;
        }

        // Проверка версии API
        JsonNode info = ctx.openapiRoot.path("info");
        String version = info.path("version").asText();
        String title = info.path("title").asText();

        if (version != null && !version.isBlank()) {
            out.add(Finding.of("/info", "N/A", 0, id(),
                    Finding.Severity.INFO, "API версия: " + version + " (" + title + ")", ""));
        }

        // Проверка устаревших версий в путях
        JsonNode paths = ctx.openapiRoot.path("paths");
        if (paths.isObject()) {
            Iterator<String> pathNames = paths.fieldNames();
            while (pathNames.hasNext()) {
                String path = pathNames.next();
                if (path.contains("/v1/") || path.contains("/v2/")) {
                    out.add(Finding.of(path, "N/A", 0, id(),
                            Finding.Severity.LOW, "Эндпоинт содержит указание версии в пути", path));
                }
            }
        }

        // Проверка серверов
        JsonNode servers = ctx.openapiRoot.path("servers");
        if (servers.isArray()) {
            for (JsonNode server : servers) {
                String url = server.path("url").asText();
                if (url != null && !url.isBlank()) {
                    if (url.contains("staging") || url.contains("test") || url.contains("dev")) {
                        out.add(Finding.of(url, "N/A", 0, id(),
                                Finding.Severity.MEDIUM, "Сервер может быть тестовым/staging", url));
                    }
                }
            }
        }

        return out;
    }
}