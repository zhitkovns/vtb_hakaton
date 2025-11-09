package securityscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfWriter;
import securityscanner.core.model.Finding;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ReportWriter {

    private final ObjectMapper om = new ObjectMapper();

    public static class Meta {
        public String title;
        public String openapi;
        public String baseUrl;
        public String generatedAt;
    }

    public static class Report {
        public Meta meta;
        public java.util.List<Finding> findings;
    }

    public File writeJson(String title, String openapi, String baseUrl, java.util.List<Finding> findings) throws Exception {
        ensureDir();
        Report r = new Report();
        r.meta = new Meta();
        r.meta.title = title;
        r.meta.openapi = openapi;
        r.meta.baseUrl = baseUrl;
        r.meta.generatedAt = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        r.findings = findings;

        String name = "VirtualBankAPI-" + timestamp() + ".json";
        File file = new File("target/reports/" + name);
        om.writerWithDefaultPrettyPrinter().writeValue(file, r);
        return file;
    }

    public File writePdf(String title, String openapi, String baseUrl, java.util.List<Finding> findings) throws Exception {
        ensureDir();
        String name = "VirtualBankAPI-" + timestamp() + ".pdf";
        File file = new File("target/reports/" + name);

        Document doc = new Document(PageSize.A4.rotate()); // Ландшафтная ориентация для лучшего отображения
        PdfWriter.getInstance(doc, new FileOutputStream(file));
        doc.open();
        
        Font h1 = new Font(Font.HELVETICA, 16, Font.BOLD);
        Font h2 = new Font(Font.HELVETICA, 12, Font.BOLD);
        Font h3 = new Font(Font.HELVETICA, 10, Font.BOLD);
        Font txt = new Font(Font.HELVETICA, 8, Font.NORMAL);
        Font bold = new Font(Font.HELVETICA, 8, Font.BOLD);

        // Заголовок
        doc.add(new Paragraph(title, h1));
        doc.add(new Paragraph("OpenAPI: " + openapi, txt));
        doc.add(new Paragraph("Base URL: " + baseUrl, txt));
        doc.add(new Paragraph("Generated: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), txt));
        doc.add(new Paragraph(" ", txt));

        // Статистика
        long highCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.HIGH).count();
        long mediumCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.MEDIUM).count();
        long lowCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.LOW).count();
        long infoCount = findings.stream().filter(finding -> finding.severity == Finding.Severity.INFO).count();
        long total = findings.size();

        // Summary
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

        // Security Findings by OWASP Category
        doc.add(new Paragraph("Security Findings by OWASP Category:", h2));
        
        Map<String, Integer> owaspCounts = new HashMap<>();
        Map<String, Integer> owaspSeverityCounts = new HashMap<>();
        
        for (Finding finding : findings) {
            if (finding.owasp != null && finding.owasp.startsWith("API")) {
                owaspCounts.put(finding.owasp, owaspCounts.getOrDefault(finding.owasp, 0) + 1);
                
                // Подсчет по severity для OWASP категорий
                String severityKey = finding.owasp + "_" + finding.severity;
                owaspSeverityCounts.put(severityKey, owaspSeverityCounts.getOrDefault(severityKey, 0) + 1);
            }
        }
        
        for (Map.Entry<String, Integer> entry : owaspCounts.entrySet()) {
            StringBuilder severityBreakdown = new StringBuilder();
            for (Finding.Severity severity : Finding.Severity.values()) {
                String key = entry.getKey() + "_" + severity;
                Integer count = owaspSeverityCounts.get(key);
                if (count != null && count > 0) {
                    severityBreakdown.append(severity).append(":").append(count).append(" ");
                }
            }
            doc.add(new Paragraph(entry.getKey() + ": " + entry.getValue() + " findings (" + severityBreakdown.toString().trim() + ")", txt));
        }
        doc.add(new Paragraph(" ", txt));

        // Detailed Findings Table - Упрощенная версия без Evidence
        doc.add(new Paragraph("Detailed Security Findings:", h2));
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
        doc.add(new Paragraph("• Implement missing security headers (HSTS, CSP, X-Content-Type-Options)", txt));
        doc.add(new Paragraph("• Monitor and tune rate limiting thresholds", txt));
        doc.add(new Paragraph("• Regular security testing and code review", txt));
        doc.add(new Paragraph("• Ensure proper error handling without information disclosure", txt));
        doc.add(new Paragraph("• Implement comprehensive logging and monitoring", txt));
        doc.add(new Paragraph("• Keep dependencies and frameworks updated", txt));
        
        doc.close();
        return file;
    }

private PdfPCell createCell(String content, Font font) {
    String cleanContent = cleanText(content);
    PdfPCell cell = new PdfPCell(new Phrase(cleanContent, font));
    cell.setPadding(4);
    cell.setBorderWidth(0.5f);
    return cell;
}

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

    private static String timestamp() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
    }
    
    private static void ensureDir() throws Exception {
        Files.createDirectories(new File("target/reports").toPath());
    }
    
    private static String trim(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
    
    private static String safe(String s) { 
        return s == null ? "" : s; 
    }
    private String cleanText(String text) {
    if (text == null) return "";
    
    // Убираем некорректные символы и фразы
    return text.replace("synchrotriking", "аутентификации")
              .replace("was the main tool in your app", "невалиден или просрочен")
              .replace("ProxyServer security assurance", "Отсутствует security заголовок")
              .replaceAll("[^\\x20-\\x7Eа-яА-ЯёЁ]", "") // Только ASCII и кириллица
              .trim();
}
}