package dev.wstgmapper;

import java.util.ArrayList;
import java.util.List;

public final class TextUtil {

    private TextUtil() {
    }

    public static String escapeHtml(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * Turns a compact "Target: X | Point: Y | Payload: Z | Method: W"
     * checklist guidance string into separate, labeled lines so it reads
     * as an actual step-by-step manual test instead of one dense run-on
     * sentence. Falls back to the text unchanged if it isn't '|'-separated.
     */
    public static List<String> formatGuidance(String guidance) {
        List<String> out = new ArrayList<>();
        if (guidance == null || guidance.isEmpty()) {
            out.add("");
            return out;
        }
        String[] parts = guidance.split("\\|");
        if (parts.length <= 1) {
            out.add(guidance);
            return out;
        }
        for (String p : parts) {
            out.add(p.trim());
        }
        return out;
    }
}
