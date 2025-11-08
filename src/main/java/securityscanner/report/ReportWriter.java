package securityscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPTable;
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
        public java.util.List<Finding> findings; // Явно указываем java.util.List
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

        Document doc = new Document(PageSize.A4);
        PdfWriter.getInstance(doc, new FileOutputStream(file));
        doc.open();
        Font h1 = new Font(Font.HELVETICA, 16, Font.BOLD);
        Font h2 = new Font(Font.HELVETICA, 12, Font.BOLD);
        Font txt = new Font(Font.HELVETICA, 10, Font.NORMAL);

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
        doc.add(new Paragraph("Total Findings: " + total, txt));
        doc.add(new Paragraph("High: " + highCount + ", Medium: " + mediumCount + ", Low: " + lowCount + ", Info: " + infoCount, txt));
        doc.add(new Paragraph(" ", txt));

        // Key Findings by OWASP
        doc.add(new Paragraph("Security Findings by OWASP Category:", h2));
        
        // Простая группировка по OWASP категориям
        Map<String, Integer> owaspCounts = new HashMap<>();
        for (Finding finding : findings) {
            if (finding.owasp != null && finding.owasp.startsWith("API")) {
                owaspCounts.put(finding.owasp, owaspCounts.getOrDefault(finding.owasp, 0) + 1);
            }
        }
        
        for (Map.Entry<String, Integer> entry : owaspCounts.entrySet()) {
            doc.add(new Paragraph(entry.getKey() + ": " + entry.getValue() + " findings", txt));
        }
        doc.add(new Paragraph(" ", txt));

        // Detailed Findings Table
        PdfPTable table = new PdfPTable(6);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{18, 10, 10, 12, 25, 25});
        table.addCell("Endpoint");
        table.addCell("Method");
        table.addCell("Status");
        table.addCell("Type/Severity");
        table.addCell("Message");
        table.addCell("Evidence");

        for (Finding finding : findings) {
            table.addCell(safe(finding.endpoint));
            table.addCell(safe(finding.method));
            table.addCell(String.valueOf(finding.status));
            table.addCell(safe(finding.owasp) + " / " + (finding.severity != null ? finding.severity : ""));
            table.addCell(safe(finding.message));
            table.addCell(safe(trim(finding.evidence, 600)));
        }
        doc.add(table);
        
        // Recommendations
        doc.add(new Paragraph(" "));
        doc.add(new Paragraph("Recommendations:", h2));
        doc.add(new Paragraph("• Implement missing security headers", txt));
        doc.add(new Paragraph("• Monitor rate limiting thresholds", txt));
        doc.add(new Paragraph("• Regular security testing", txt));
        
        doc.close();
        return file;
    }

    private static String timestamp() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
    }
    
    private static void ensureDir() throws Exception {
        Files.createDirectories(new File("target/reports").toPath());
    }
    
    private static String trim(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "...(truncated)" : s;
    }
    
    private static String safe(String s) { 
        return s == null ? "" : s; 
    }
}