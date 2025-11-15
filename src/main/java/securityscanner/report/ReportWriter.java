package securityscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfWriter;
import securityscanner.core.model.Finding;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Генератор отчетов в форматах JSON и PDF
 * Создает структурированные отчеты с результатами сканирования безопасности
 */
public class ReportWriter {

    private final ObjectMapper om = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private String reportsDir = "reports";

    /**
     * Мета-информация для отчета
     */
    public static class Meta {
        public String title;
        public String openapi;
        public String baseUrl;
        public String generatedAt;
        public String bankName;
        public String scannerVersion = "1.0";
        public ScanSummary summary;

        public Meta() {}
    }

    /**
     * Сводка по сканированию
     */
    public static class ScanSummary {
        public int totalFindings;
        public int high;
        public int medium;
        public int low;
        public int info;
        public Map<String, Integer> categoryCounts = new HashMap<>();

        public ScanSummary() {}
    }

    /**
     * Структура полного отчета
     */
    public static class Report {
        public Meta meta;
        public java.util.List<Finding> findings;

        public Report() {}
    }

    /**
     * Генерирует отчет в формата JSON
     * @param title заголовок отчета
     * @param openapi путь к OpenAPI спецификации
     * @param baseUrl базовый URL API
     * @param findings список найденных проблем
     * @return файл с JSON отчетом
     */
    public File writeJson(String title, String openapi, String baseUrl, java.util.List<Finding> findings) throws Exception {
        ensureReportsDir();
        
        // Создаем сводку
        ScanSummary summary = createSummary(findings);
        
        Report r = new Report();
        r.meta = new Meta();

        String bankName = extractBankNameFromUrl(baseUrl);
        r.meta.title = bankName + " API Security Report";
        r.meta.openapi = openapi;
        r.meta.baseUrl = baseUrl;
        r.meta.generatedAt = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        r.meta.bankName = bankName;
        r.meta.summary = summary;
        r.findings = findings;

        String name = generateReportName(extractBankCodeFromUrl(baseUrl), "json");
        File file = new File(reportsDir + "/" + name);
        om.writeValue(file, r);
        return file;
    }
    
    /**
     * Создает сводку по findings с полным покрытием OWASP API Top 10
     */
    private ScanSummary createSummary(java.util.List<Finding> findings) {
        ScanSummary summary = new ScanSummary();
        summary.totalFindings = findings.size();
        
        // Подсчет по severity
        summary.high = (int) findings.stream().filter(f -> f.severity == Finding.Severity.HIGH).count();
        summary.medium = (int) findings.stream().filter(f -> f.severity == Finding.Severity.MEDIUM).count();
        summary.low = (int) findings.stream().filter(f -> f.severity == Finding.Severity.LOW).count();
        summary.info = (int) findings.stream().filter(f -> f.severity == Finding.Severity.INFO).count();
        
        // Полный список OWASP API Top 10 категорий в порядке
        Map<String, Integer> categoryCounts = new HashMap<>();
        
        // OWASP API Security Top 10 (в порядке)
        String[] owaspCategories = {
            "API1", "API2", "API3", "API4", "API5", 
            "API6", "API7", "API8", "API9", "API10"
        };
        
        // Дополнительные проверки
        String[] additionalCategories = {
            "API", "ConsentManagement", "ContractMatch", "ContractCheck",
            "API8:Injection", "API8:SecurityHeaders", "API8:SecurityMisconfig"
        };
        
        // Инициализируем все OWASP категории с 0
        for (String category : owaspCategories) {
            categoryCounts.put(category, 0);
        }
        
        // Инициализируем дополнительные категории с 0
        for (String category : additionalCategories) {
            categoryCounts.put(category, 0);
        }
        
        // Подсчитываем реальные findings
        for (Finding finding : findings) {
            if (finding.owasp != null && !finding.owasp.isBlank()) {
                // Для OWASP категорий берем основную часть (API1, API2, etc)
                String category = finding.owasp;
                if (category.contains(":")) {
                    category = category.split(":")[0];
                }
                
                // Увеличиваем счетчик для категории
                categoryCounts.put(category, categoryCounts.getOrDefault(category, 0) + 1);
                
                // Также считаем полные OWASP коды (API8:Injection и т.д.)
                if (finding.owasp.contains(":")) {
                    categoryCounts.put(finding.owasp, categoryCounts.getOrDefault(finding.owasp, 0) + 1);
                }
            }
        }
        
        summary.categoryCounts = categoryCounts;
        
        return summary;
    }

    /**
     * Генерирует отчет в формате PDF
     * @param title заголовок отчета
     * @param openapi путь к OpenAPI спецификации
     * @param baseUrl базовый URL API
     * @param findings список найденных проблем
     * @return файл с PDF отчетом
     */
    public File writePdf(String title, String openapi, String baseUrl, java.util.List<Finding> findings) throws Exception {
        ensureReportsDir();
        String name = generateReportName(extractBankCodeFromUrl(baseUrl), "pdf");
        File file = new File(reportsDir + "/" + name);

        // Создание PDF документа с ландшафтной ориентацией
        Document doc = new Document(PageSize.A4.rotate());
        PdfWriter.getInstance(doc, new FileOutputStream(file));
        doc.open();
        
        // Настройка шрифтов
        Font h1 = new Font(Font.HELVETICA, 16, Font.BOLD);
        Font h2 = new Font(Font.HELVETICA, 12, Font.BOLD);
        Font h3 = new Font(Font.HELVETICA, 10, Font.BOLD);
        Font txt = new Font(Font.HELVETICA, 8, Font.NORMAL);
        Font bold = new Font(Font.HELVETICA, 8, Font.BOLD);

        // Определяем название банка из URL
        String bankName = getBankDisplayName(baseUrl);
        
        // Заголовок отчета с названием банка
        doc.add(new Paragraph(bankName + " API Security Report", h1));
        doc.add(new Paragraph("Base URL: " + baseUrl, txt));
        doc.add(new Paragraph("Generated: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), txt));
        doc.add(new Paragraph(" ", txt));

        // Статистика findings
        long highCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.HIGH).count();
        long mediumCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.MEDIUM).count();
        long lowCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.LOW).count();
        long infoCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.INFO).count();
        long total = findings.size();

        // Summary секция
        doc.add(new Paragraph("Scan Summary:", h2));
        doc.add(new Paragraph("Total Findings: " + total, bold));
        doc.add(new Paragraph("High: " + highCount + ", Medium: " + mediumCount + ", Low: " + lowCount + ", Info: " + infoCount, txt));
        doc.add(new Paragraph(" ", txt));

        // Critical Findings Summary
        if (highCount > 0) {
            doc.add(new Paragraph("Critical Findings Summary:", h2));
            findings.stream()
                .filter(f -> f.severity == Finding.Severity.HIGH)
                .forEach(f -> {
                    doc.add(new Paragraph("• " + f.message + " [" + f.endpoint + "]", txt));
                });
            doc.add(new Paragraph(" ", txt));
        }

        // Security Findings by OWASP API Top 10 - строго по порядку
        doc.add(new Paragraph("OWASP API Security Top 10 Security Assessment:", h2));
        doc.add(new Paragraph(" "));

        // Полный список OWASP категорий в порядке
        String[][] owaspCategories = {
            {"API1", "Broken Object Level Authorization", "Небезопасный доступ к объектам"},
            {"API2", "Broken Authentication", "Проблемы аутентификации"}, 
            {"API3", "Broken Object Property Level Authorization", "Небезопасный доступ к свойствам объектов"},
            {"API4", "Unrestricted Resource Consumption", "Неограниченное потребление ресурсов"},
            {"API5", "Broken Function Level Authorization", "Небезопасный доступ к функциям"},
            {"API6", "Unrestricted Access to Sensitive Business Flows", "Неограниченный доступ к бизнес-процессам"},
            {"API7", "Server Side Request Forgery", "Подделка запросов на стороне сервера"},
            {"API8", "Security Misconfiguration", "Ошибки конфигурации безопасности"},
            {"API9", "Improper Inventory Management", "Некорректное управление инвентарем"},
            {"API10", "Unsafe Consumption of APIs", "Небезопасное потребление API"}
        };

        ScanSummary summary = createSummary(findings);

        // Создаем таблицу для OWASP Top 10
        PdfPTable owaspTable = new PdfPTable(4);
        owaspTable.setWidthPercentage(100);
        owaspTable.setWidths(new float[]{10, 30, 40, 20});
        owaspTable.addCell(createCell("Category", h3));
        owaspTable.addCell(createCell("Title", h3));
        owaspTable.addCell(createCell("Description", h3));
        owaspTable.addCell(createCell("Findings", h3));

        for (String[] category : owaspCategories) {
            String categoryCode = category[0];
            Integer count = summary.categoryCounts.get(categoryCode);
            if (count == null) count = 0;
            
            owaspTable.addCell(createCell(categoryCode, txt));
            owaspTable.addCell(createCell(category[1], txt));
            owaspTable.addCell(createCell(category[2], txt));
            owaspTable.addCell(createCell(String.valueOf(count), txt));
        }

        doc.add(owaspTable);
        doc.add(new Paragraph(" "));

        // Дополнительные проверки
        doc.add(new Paragraph("Additional Security Checks:", h2));
        doc.add(new Paragraph(" "));

        String[][] additionalChecks = {
            {"API Health", "Проверка доступности эндпоинтов"},
            {"Injection Testing", "Тестирование на SQL/NoSQL инъекции"},
            {"Consent Management", "Управление согласиями"},
            {"Contract Validation", "Валидация соответствия спецификации"}
        };

        PdfPTable additionalTable = new PdfPTable(3);
        additionalTable.setWidthPercentage(100);
        additionalTable.setWidths(new float[]{30, 50, 20});
        additionalTable.addCell(createCell("Check Type", h3));
        additionalTable.addCell(createCell("Description", h3));
        additionalTable.addCell(createCell("Findings", h3));

        for (String[] check : additionalChecks) {
            String code = getCategoryCode(check[0]);
            Integer count = summary.categoryCounts.get(code);
            if (count == null) count = 0;
            
            additionalTable.addCell(createCell(check[0], txt));
            additionalTable.addCell(createCell(check[1], txt));
            additionalTable.addCell(createCell(String.valueOf(count), txt));
        }

        doc.add(additionalTable);
        doc.add(new Paragraph(" "));

        // Detailed Findings Table с отступом сверху
        doc.add(new Paragraph("Detailed Security Findings:", h2));
        doc.add(new Paragraph(" ")); // ДОБАВЛЕН ОТСТУП ПЕРЕД ТАБЛИЦЕЙ
        
        PdfPTable table = new PdfPTable(5);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{15, 8, 8, 20, 49});
        table.addCell(createCell("Endpoint", h3));
        table.addCell(createCell("Method", h3));
        table.addCell(createCell("Status", h3));
        table.addCell(createCell("Type/Severity", h3));
        table.addCell(createCell("Message & Recommendation", h3));

        // Сортируем findings по severity (HIGH first)
        java.util.List<Finding> sortedFindings = new ArrayList<>(findings);
        sortedFindings.sort((f1, f2) -> {
            int severityCompare = f2.severity.compareTo(f1.severity); // HIGH first
            if (severityCompare != 0) return severityCompare;
            return f1.endpoint.compareTo(f2.endpoint);
        });

        for (Finding finding : sortedFindings) {
            table.addCell(createCell(safe(trim(finding.endpoint, 30)), txt));
            table.addCell(createCell(safe(finding.method), txt));
            table.addCell(createCell(String.valueOf(finding.status), txt));
            
            String typeSeverity = safe(finding.owasp) + " / " + 
                                (finding.severity != null ? finding.severity.toString() : "");
            table.addCell(createCell(typeSeverity, txt));
            
            String messageAndRecommendation = safe(finding.message);
            if (finding.recommendation != null && !finding.recommendation.isBlank()) {
                messageAndRecommendation += "\n\nРекомендация: " + safe(finding.recommendation);
            }
            table.addCell(createCell(messageAndRecommendation, txt));
        }
        doc.add(table);
        
        // Executive Summary and Recommendations
        doc.add(new Paragraph(" "));
        doc.add(new Paragraph("Executive Recommendations:", h2));
        
        // Группируем рекомендации по категориям
        Map<String, java.util.List<String>> categorizedRecs = new HashMap<>();
        
        for (Finding finding : findings) {
            if (finding.recommendation != null && !finding.recommendation.isBlank() && 
                finding.severity != Finding.Severity.INFO) {
                
                String category = getRecommendationCategory(finding);
                categorizedRecs.computeIfAbsent(category, k -> new ArrayList<>())
                              .add(finding.recommendation);
            }
        }
        
        for (Map.Entry<String, java.util.List<String>> entry : categorizedRecs.entrySet()) {
            doc.add(new Paragraph(entry.getKey() + ":", h3));
            // Убираем дубликаты рекомендаций
            Set<String> uniqueRecs = new LinkedHashSet<>(entry.getValue());
            for (String rec : uniqueRecs) {
                doc.add(new Paragraph("• " + rec, txt));
            }
            doc.add(new Paragraph(" "));
        }

        // Standard Recommendations
        doc.add(new Paragraph("Standard Security Recommendations:", h2));
        doc.add(new Paragraph("• Реализуйте недостающие security заголовки (HSTS, CSP, X-Content-Type-Options)", txt));
        doc.add(new Paragraph("• Настройте и мониторьте ограничения частоты запросов (rate limiting)", txt));
        doc.add(new Paragraph("• Регулярное тестирование безопасности и код-ревью", txt));
        doc.add(new Paragraph("• Обеспечьте правильную обработку ошибок без раскрытия информации", txt));
        doc.add(new Paragraph("• Внедрите комплексное логирование и мониторинг", txt));
        doc.add(new Paragraph("• Обновляйте зависимости и фреймворки", txt));
        
        doc.close();
        return file;
    }

    /**
     * Извлекает полное название банка из URL
     */
    private String extractBankNameFromUrl(String url) {
        if (url == null) return "Unknown Bank";
        if (url.contains("vbank")) return "Virtual Bank";
        if (url.contains("abank")) return "Awesome Bank";
        if (url.contains("sbank")) return "Smart Bank";
        return "Unknown Bank";
    }

    /**
     * Извлекает код банка из URL для имени файла
     */
    private String extractBankCodeFromUrl(String url) {
        if (url == null) return "unknown";
        if (url.contains("vbank")) return "VirtualBank";
        if (url.contains("abank")) return "AwesomeBank";
        if (url.contains("sbank")) return "SmartBank";
        return "UnknownBank";
    }

    /**
     * Возвращает отображаемое название банка
     */
    private String getBankDisplayName(String baseUrl) {
        return extractBankNameFromUrl(baseUrl);
    }

    /**
     * Генерирует имя файла отчета с кодом банка и timestamp
     */
    private String generateReportName(String bankCode, String extension) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        return bankCode + "-SecurityReport-" + timestamp + "." + extension;
    }

    /**
     * Создает папку reports если она не существует
     */
    private void ensureReportsDir() throws Exception {
        Path reportsPath = Paths.get(reportsDir);
        if (!Files.exists(reportsPath)) {
            Files.createDirectories(reportsPath);
            System.out.println("Created reports directory: " + reportsPath.toAbsolutePath());
        }
    }

    /**
     * Создает ячейку таблицы PDF с заданным содержимым и шрифтом
     */
    private PdfPCell createCell(String content, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(content, font));
        cell.setPadding(4);
        cell.setBorderWidth(0.5f);
        return cell;
    }

    /**
     * Определяет категорию рекомендации на основе типа finding
     */
    private String getRecommendationCategory(Finding finding) {
        if (finding.owasp != null) {
            if (finding.owasp.contains("BOLA")) return "Access Control";
            if (finding.owasp.contains("Auth")) return "Authentication";
            if (finding.owasp.contains("Injection")) return "Input Validation";
            if (finding.owasp.contains("Resource")) return "Performance & Rate Limiting";
            if (finding.owasp.contains("Misconfig")) return "Security Configuration";
        }
        
        if (finding.message != null) {
            if (finding.message.contains("schema") || finding.message.contains("contract")) 
                return "API Contract Compliance";
            if (finding.message.contains("token") || finding.message.contains("auth")) 
                return "Authentication";
            if (finding.message.contains("rate") || finding.message.contains("limit")) 
                return "Performance & Rate Limiting";
        }
        
        return "General Security";
    }
    
    /**
     * Преобразует название проверки в код категории
     */
    private String getCategoryCode(String categoryName) {
        if (categoryName.contains("Health")) return "API";
        if (categoryName.contains("Injection")) return "API8:Injection"; 
        if (categoryName.contains("Consent")) return "ConsentManagement";
        if (categoryName.contains("Contract")) return "ContractMatch";
        return categoryName;
    }
    
    /**
     * Обрезает строку до максимальной длины
     */
    private static String trim(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
    
    /**
     * Защищает от null значений
     */
    private static String safe(String s) { 
        return s == null ? "" : s; 
    }
}