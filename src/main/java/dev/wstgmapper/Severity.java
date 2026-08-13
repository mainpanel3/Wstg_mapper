package dev.wstgmapper;

import java.awt.Color;

/**
 * This extension's own severity vocabulary for a WSTG checklist row.
 * {@code rank} controls merging: when a new Burp Scanner finding is
 * merged onto a WSTG id, its severity only ever raises (never lowers)
 * the severity already recorded there - see FindingsStore.mergeIssue.
 */
public enum Severity {
    SAFE("Not Found", new Color(0x10, 0xB9, 0x81), 0),
    MANUAL("Manual Testing Required", new Color(0x94, 0xA3, 0xB8), 1),
    INFO("Informational", new Color(0x38, 0xBD, 0xF8), 2),
    ERROR("Error During Merge", new Color(0x64, 0x74, 0x8B), 3),
    SUSPICIOUS("Suspicious / Needs Review", new Color(0xF5, 0x9E, 0x0B), 4),
    VULN("Vulnerable", new Color(0xE1, 0x1D, 0x48), 5);

    private final String label;
    private final Color color;
    private final int rank;

    Severity(String label, Color color, int rank) {
        this.label = label;
        this.color = color;
        this.rank = rank;
    }

    public String label() {
        return label;
    }

    public Color color() {
        return color;
    }

    public int rank() {
        return rank;
    }

    /** Maps a Burp AuditIssueSeverity name (HIGH/MEDIUM/LOW/INFORMATION/FALSE_POSITIVE) onto this vocabulary. */
    public static Severity fromBurpSeverity(String burpSeverityName) {
        if (burpSeverityName == null) {
            return INFO;
        }
        return switch (burpSeverityName) {
            case "HIGH" -> VULN;
            case "MEDIUM", "LOW" -> SUSPICIOUS;
            case "INFORMATION" -> INFO;
            case "FALSE_POSITIVE" -> SAFE;
            default -> INFO;
        };
    }
}
