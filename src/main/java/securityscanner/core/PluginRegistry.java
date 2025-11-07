package securityscanner.core;

import java.util.ArrayList;
import java.util.List;

public class PluginRegistry {
    private final List<SecurityPlugin> plugins = new ArrayList<>();

    public PluginRegistry register(SecurityPlugin plugin) {
        plugins.add(plugin);
        return this;
    }

    public List<SecurityPlugin> all() {
        return plugins;
    }
}
