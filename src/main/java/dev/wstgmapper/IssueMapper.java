package dev.wstgmapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps a Burp Scanner issue name onto one or more WSTG checklist ids by
 * lower-cased substring matching against a fixed keyword table. This is
 * the extension's only source of automated findings - it does not run
 * any HTTP probes of its own. A single Burp issue can map to more than
 * one WSTG id (e.g. cookie flag issues touch both session management and
 * session hijacking). If nothing matches, the issue falls back to
 * {@link ChecklistData#GENERAL_FINDINGS_ID} so nothing is ever silently
 * dropped just because its name wasn't recognized.
 */
public final class IssueMapper {

    private static final Map<String, List<String>> KEYWORD_TO_WSTG = new LinkedHashMap<>();

    private static void put(String keyword, String... ids) {
        KEYWORD_TO_WSTG.put(keyword, Collections.unmodifiableList(Arrays.asList(ids)));
    }

    static {
        put("sql injection", "WSTG-INPV-05");
        put("os command injection", "WSTG-INPV-13");
        put("ldap injection", "WSTG-INPV-06");
        put("xpath injection", "WSTG-INPV-10");
        put("xml external entity", "WSTG-INPV-08");
        put("xml injection", "WSTG-INPV-08");
        put("xml entity expansion", "WSTG-INPV-08");
        put("server-side template injection", "WSTG-INPV-18");
        put("server-side request forgery", "WSTG-INPV-19");
        put("out-of-band resource load", "WSTG-INPV-19");
        put("external service interaction", "WSTG-INPV-19");
        put("smuggling", "WSTG-INPV-16");
        put("desync", "WSTG-INPV-16");
        put("request smuggling", "WSTG-INPV-16");
        put("cache poisoning", "WSTG-INPV-16");
        put("http response header injection", "WSTG-INPV-16");
        put("crlf", "WSTG-INPV-16");
        put("http header injection", "WSTG-INPV-16");
        put("cross-site scripting (dom", "WSTG-CLNT-01");
        put("cross-site scripting (reflected)", "WSTG-INPV-01");
        put("cross-site scripting (stored)", "WSTG-INPV-02");
        put("file path traversal", "WSTG-AUTHZ-01");
        put("file path manipulation", "WSTG-AUTHZ-01");
        put("open redirection", "WSTG-CLNT-04");
        put("cross-origin resource sharing", "WSTG-CLNT-07");
        put("clickjacking", "WSTG-CLNT-09");
        put("frameable response", "WSTG-CLNT-09");
        put("cross-site request forgery", "WSTG-SESS-05");
        put("cookie without httponly", "WSTG-SESS-02", "WSTG-SESS-09");
        put("cookie without secure", "WSTG-SESS-02");
        put("cookie scoped", "WSTG-SESS-02");
        put("session token", "WSTG-SESS-01");
        put("strict transport security", "WSTG-CONF-07");
        put("content security policy", "WSTG-CONF-07");
        put("ssl", "WSTG-CRYP-01");
        put("tls", "WSTG-CRYP-01");
        put("unencrypted communications", "WSTG-CRYP-03");
        put("password field submitted using get", "WSTG-AUTHN-01");
        put("password field with autocomplete", "WSTG-AUTHN-07");
        put("source code disclosure", "WSTG-CONF-05");
        put("backup file", "WSTG-CONF-04");
        put("directory listing", "WSTG-CONF-04", "WSTG-CONF-05");
        put("robots.txt", "WSTG-INFO-03");
        put("html injection", "WSTG-CLNT-03");
        put("flash cross-domain policy", "WSTG-CLNT-08");
        put("silverlight cross-domain policy", "WSTG-CONF-08");
        put("cross-domain policy", "WSTG-CONF-08");
        put("browser cross-site scripting protection disabled", "WSTG-CONF-07");
        put("cacheable https response", "WSTG-AUTHN-06");
        put("browser cache", "WSTG-AUTHN-06");
        put("input returned in response", "WSTG-INPV-01");
        put("vulnerable javascript dependency", "WSTG-INFO-09");
        put("out-of-date version", "WSTG-INFO-09");
        put("private ip addresses disclosed", "WSTG-INFO-10");
        put("email addresses disclosed", "WSTG-INFO-05");
        put("private key", "WSTG-CRYP-04");
        put("weak", "WSTG-CRYP-04");
        put("http parameter pollution", "WSTG-INPV-04");
        put("http verb tampering", "WSTG-INPV-03");
        put("buffer overflow", "WSTG-INPV-14");
        put("server-side includes", "WSTG-INPV-09");
        put("suspicious input transformation", "WSTG-INPV-01");
        put("stack trace", "WSTG-ERRH-02");
        put("application error message", "WSTG-ERRH-01");
        put("database error message", "WSTG-ERRH-01");
    }

    /** Never returns an empty list - falls back to GENERAL_FINDINGS_ID. */
    public static List<String> mapIssueToWstgIds(String issueName) {
        String name = issueName == null ? "" : issueName.toLowerCase();
        List<String> matched = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : KEYWORD_TO_WSTG.entrySet()) {
            if (name.contains(entry.getKey())) {
                for (String wid : entry.getValue()) {
                    if (!matched.contains(wid)) {
                        matched.add(wid);
                    }
                }
            }
        }
        if (matched.isEmpty()) {
            matched.add(ChecklistData.GENERAL_FINDINGS_ID);
        }
        return matched;
    }

    private IssueMapper() {
    }
}
