package dev.wstgmapper;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The extension's only source of findings: every WSTG id starts as
 * MANUAL with its checklist guidance, and gets enriched (severity raised,
 * a note appended) whenever a Burp Scanner issue maps onto it via
 * {@link IssueMapper}. This class runs no HTTP probes of its own -
 * scanning stays entirely inside Burp; this just organizes what Burp
 * already found.
 */
public final class FindingsStore {

    /** Result of attempting to merge one Burp issue, for accurate status-line counts. */
    public enum MergeResult {
        NEW_MAPPED,
        NEW_UNMAPPED,
        DUPLICATE
    }

    private final Map<String, Finding> findings = new LinkedHashMap<>();
    private final Set<String> seenIssueKeys = new HashSet<>();

    public FindingsStore() {
        reset();
    }

    /** (Re)builds every WSTG id back to its initial MANUAL/guidance state and forgets merged issues. */
    public void reset() {
        findings.clear();
        seenIssueKeys.clear();
        for (ChecklistItem item : ChecklistData.ITEMS) {
            findings.put(item.id(), new Finding(Severity.MANUAL, item.guidance()));
        }
    }

    public Finding get(String wstgId) {
        return findings.get(wstgId);
    }

    /**
     * Maps one Burp AuditIssue onto matching WSTG id(s) - or, if nothing
     * matches, onto the GENERAL_FINDINGS_ID catch-all - and folds it into
     * this store. Idempotent: the same (name, baseUrl) pair merged twice
     * returns DUPLICATE the second time, so callers (live handler and the
     * manual "Import" button) never double count.
     */
    public MergeResult mergeIssue(AuditIssue issue) {
        String name;
        String baseUrl;
        Severity localSeverity;
        String confidenceLabel;
        String severityLabel;
        try {
            name = issue.name();
            baseUrl = issue.baseUrl();
            severityLabel = issue.severity().name();
            confidenceLabel = issue.confidence().name();
            localSeverity = Severity.fromBurpSeverity(severityLabel);
        } catch (Exception e) {
            return MergeResult.DUPLICATE;
        }

        String key = name + "\u0000" + baseUrl;
        if (!seenIssueKeys.add(key)) {
            return MergeResult.DUPLICATE;
        }

        List<String> wstgIds = IssueMapper.mapIssueToWstgIds(name);
        boolean isUnmapped = wstgIds.size() == 1 && wstgIds.get(0).equals(ChecklistData.GENERAL_FINDINGS_ID);

        String note = "Burp Scanner: " + name + " [" + severityLabel + " / " + confidenceLabel
                + " confidence] - " + baseUrl;

        for (String wid : wstgIds) {
            Finding f = findings.get(wid);
            if (f == null) {
                continue;
            }
            f.addScannerNote(note);
            f.raiseSeverity(localSeverity);
            // Note: guidance is deliberately never overwritten here - see Finding's
            // javadoc. Scanner findings are shown separately, underneath it.
        }
        return isUnmapped ? MergeResult.NEW_UNMAPPED : MergeResult.NEW_MAPPED;
    }
}
