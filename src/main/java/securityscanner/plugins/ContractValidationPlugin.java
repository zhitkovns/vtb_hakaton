// securityscanner/plugins/ContractValidationPlugin.java
package securityscanner.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;

import java.util.*;

public class ContractValidationPlugin implements SecurityPlugin {
    @Override public String id() { return "ContractValidation"; }
    @Override public String title() { return "OpenAPI Contract Validation"; }
    @Override public String description() { return "Проверка соответствия API спецификации OpenAPI"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();
        
        if (ctx.openapiRoot == null) {
            out.add(Finding.of("N/A", "N/A", 0, id(),
                Finding.Severity.MEDIUM, "OpenAPI спецификация не загружена", ""));
            return out;
        }

        // Проверка обязательных полей в спецификации
        JsonNode paths = ctx.openapiRoot.path("paths");
        if (paths.isMissingNode() || !paths.isObject()) {
            out.add(Finding.of("N/A", "N/A", 0, id(),
                Finding.Severity.HIGH, "Спецификация не содержит paths", ""));
            return out;
        }

        // Проверка security схем
        JsonNode components = ctx.openapiRoot.path("components");
        JsonNode securitySchemes = components.path("securitySchemes");
        if (securitySchemes.isMissingNode()) {
            out.add(Finding.of("N/A", "N/A", 0, id(),
                Finding.Severity.MEDIUM, "Спецификация не определяет security схемы", ""));
        }

        return out;
    }
}