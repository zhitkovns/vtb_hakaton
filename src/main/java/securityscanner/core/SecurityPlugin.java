package securityscanner.core;

import securityscanner.core.model.Finding;

import java.util.List;

public interface SecurityPlugin {
    String id();              // например "API1:BOLA"
    String title();           // короткое имя
    String description();     // что делает плагин

    List<Finding> run(ExecutionContext ctx) throws Exception;
}
