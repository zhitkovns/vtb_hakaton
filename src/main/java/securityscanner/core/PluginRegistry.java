package securityscanner.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Реестр плагинов безопасности. Регистрирует все доступные плагины
 * для проверки OWASP API Top 10 и дополнительные проверки.
 */
public class PluginRegistry {
    private final List<SecurityPlugin> plugins = new ArrayList<>();

    /**
     * Регистрирует отдельный плагин в реестре
     */
    public PluginRegistry register(SecurityPlugin plugin) {
        plugins.add(plugin);
        return this;
    }

    public PluginRegistry registerAll() {
        return this
            .register(new securityscanner.plugins.APIHealthPlugin())           // Проверка здоровья API
            .register(new securityscanner.plugins.BolaPlugin())                // API1: BOLA
            .register(new securityscanner.plugins.AuthenticationPlugin())      // API2: Broken Authentication
            .register(new securityscanner.plugins.ObjectPropertyAuthPlugin())  // API3: Object Property Authorization
            .register(new securityscanner.plugins.ResourceConsumptionPlugin()) // API4: Resource Consumption
            .register(new securityscanner.plugins.BrokenFunctionAuthPlugin())  // API5: Broken Function Level Authorization
            .register(new securityscanner.plugins.BusinessFlowPlugin())        // API6: Unrestricted Business Flows
            .register(new securityscanner.plugins.SSRFPlugin())                // API7: Server Side Request Forgery
            .register(new securityscanner.plugins.SecurityMisconfigPlugin())   // API8: Security Misconfiguration
            .register(new securityscanner.plugins.InventoryManagementPlugin()) // API9: Inventory Management
            .register(new securityscanner.plugins.UnsafeConsumptionPlugin())   // API10: Unsafe Consumption
            .register(new securityscanner.plugins.InjectionPlugin());          // Доп: SQL/NoSQL Injection
    }

    /**
     * Возвращает список всех зарегистрированных плагинов
     */
    public List<SecurityPlugin> all() {
        return plugins;
    }
}