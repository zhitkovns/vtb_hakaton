package securityscanner.core;

import java.util.ArrayList;
import java.util.List;

public class PluginRegistry {
    private final List<SecurityPlugin> plugins = new ArrayList<>();

    public PluginRegistry register(SecurityPlugin plugin) {
        plugins.add(plugin);
        return this;
    }

    public PluginRegistry registerAll() {
        // OWASP API Top 10 2023 - все 10 категорий
        return this
            .register(new securityscanner.plugins.BolaPlugin())                    // API1:2023
            .register(new securityscanner.plugins.BrokenAuthPlugin())              // API2:2023
            .register(new securityscanner.plugins.ObjectPropertyAuthPlugin())      // API3:2023 - НОВАЯ
            .register(new securityscanner.plugins.ResourceConsumptionPlugin())     // API4:2023
            .register(new securityscanner.plugins.BrokenFunctionAuthPlugin())      // API5:2023
            .register(new securityscanner.plugins.BusinessFlowPlugin())            // API6:2023 - НОВАЯ
            .register(new securityscanner.plugins.SSRFPlugin())                    // API7:2023 - НОВАЯ
            .register(new securityscanner.plugins.SecurityMisconfigPlugin())       // API8:2023
            .register(new securityscanner.plugins.InventoryManagementPlugin())     // API9:2023
            .register(new securityscanner.plugins.UnsafeConsumptionPlugin());      // API10:2023
    }

    public List<SecurityPlugin> all() {
        return plugins;
    }
}