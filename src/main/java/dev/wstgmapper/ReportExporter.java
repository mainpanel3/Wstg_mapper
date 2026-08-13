package dev.wstgmapper;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ReportExporter {

    private ReportExporter() {
    }

    public static void export(Component parent, FindingsStore store) {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("wstg-scan-report.html"));
        int ret = chooser.showSaveDialog(parent);
        if (ret != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        String html = buildReportHtml(store);
        try {
            Files.write(path, html.getBytes(StandardCharsets.UTF_8));
            JOptionPane.showMessageDialog(parent, "Report saved: " + path);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(parent, "Failed to save: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    static String buildReportHtml(FindingsStore store) {
        StringBuilder p = new StringBuilder();
        p.append("<!DOCTYPE html><html lang=\"en\" dir=\"ltr\"><head><meta charset=\"UTF-8\">");
        p.append("<title>WSTG Mapping Report</title>");
        p.append("<style>");
        p.append("body{font-family:system-ui,sans-serif;background:#0f172a;color:#f1f5f9;margin:0;padding:20px;}");
        p.append("h1{color:#38bdf8;} table{width:100%;border-collapse:collapse;margin-top:10px;}");
        p.append("th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #334155;"
                + "font-size:0.85rem;vertical-align:top;}");
        p.append("th{background:#0284c7;color:#fff;} tr:hover{background:#1e293b;}");
        p.append(".badge{background:#0369a1;color:#fff;padding:3px 6px;border-radius:4px;"
                + "font-family:monospace;font-size:0.75rem;}");
        p.append(".sev{padding:3px 8px;border-radius:10px;font-size:0.75rem;font-weight:bold;color:#0f172a;}");
        p.append("pre{white-space:pre-wrap;font-size:0.8rem;background:#090d16;padding:8px;border-radius:6px;}");
        p.append("</style></head><body>");
        p.append("<h1>WSTG Mapping Report</h1>");
        p.append("<p>").append(ChecklistData.ITEMS.size()).append(" WSTG items reviewed.</p>");
        p.append("<table><tr><th>ID</th><th>Category</th><th>Title</th><th>Tool</th>"
                + "<th>Type</th><th>Status</th><th>Manual Testing Guidance</th>"
                + "<th>Burp Scanner Findings</th></tr>");

        for (ChecklistItem item : ChecklistData.ITEMS) {
            Finding f = store.get(item.id());
            boolean hasScanner = f.hasScannerIssues();
            String rowType = hasScanner ? "Manual + Burp Scanner" : "Manual only";
            var color = f.severity().color();
            String colorHex = String.format("#%02X%02X%02X", color.getRed(), color.getGreen(), color.getBlue());
            String scannerText = hasScanner ? String.join("\n", f.scannerIssues()) : "-";
            String guidanceText = String.join("\n", TextUtil.formatGuidance(f.guidance()));

            p.append("<tr>");
            p.append("<td><span class=\"badge\">").append(TextUtil.escapeHtml(item.id())).append("</span></td>");
            p.append("<td>").append(TextUtil.escapeHtml(item.category())).append("</td>");
            p.append("<td>").append(TextUtil.escapeHtml(item.title())).append("</td>");
            p.append("<td>").append(TextUtil.escapeHtml(item.tool())).append("</td>");
            p.append("<td>").append(TextUtil.escapeHtml(rowType)).append("</td>");
            p.append("<td><span class=\"sev\" style=\"background:").append(colorHex).append("\">")
                    .append(TextUtil.escapeHtml(f.severity().label())).append("</span></td>");
            p.append("<td><pre>").append(TextUtil.escapeHtml(guidanceText)).append("</pre></td>");
            p.append("<td><pre>").append(TextUtil.escapeHtml(scannerText)).append("</pre></td>");
            p.append("</tr>");
        }
        p.append("</table></body></html>");
        return p.toString();
    }
}
