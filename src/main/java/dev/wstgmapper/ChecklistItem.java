package dev.wstgmapper;

/**
 * One row of the OWASP WSTG checklist: a fixed id/category/title/tool
 * plus the manual-testing guidance text shown until (or alongside) any
 * matching Burp Scanner findings.
 */
public record ChecklistItem(String id, String category, String title, String tool, String guidance) {
}
