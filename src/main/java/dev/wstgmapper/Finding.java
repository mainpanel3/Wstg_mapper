package dev.wstgmapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Current state for one WSTG checklist id: its severity, its manual
 * testing guidance (never overwritten once set - it should stay visible
 * even after Burp finds something, since the tester still benefits from
 * seeing what to check by hand), and any Burp Scanner notes merged onto
 * it. All access happens on the Swing Event Dispatch Thread (the audit
 * issue handler always hops back to the EDT before touching this), so
 * no extra synchronization is needed here.
 */
public final class Finding {

    private Severity severity;
    private final String guidance;
    private final List<String> scannerIssues = new ArrayList<>();

    public Finding(Severity severity, String guidance) {
        this.severity = severity;
        this.guidance = guidance;
    }

    public Severity severity() {
        return severity;
    }

    public String guidance() {
        return guidance;
    }

    public List<String> scannerIssues() {
        return Collections.unmodifiableList(scannerIssues);
    }

    public boolean hasScannerIssues() {
        return !scannerIssues.isEmpty();
    }

    /** Raises severity only if the new one outranks what's already recorded. */
    void raiseSeverity(Severity candidate) {
        if (candidate.rank() > this.severity.rank()) {
            this.severity = candidate;
        }
    }

    void addScannerNote(String note) {
        scannerIssues.add(note);
    }
}
