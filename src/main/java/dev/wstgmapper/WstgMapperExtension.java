package dev.wstgmapper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import javax.swing.SwingUtilities;

/**
 * WSTG Mapper - a pure mapper/organizer for the 96-item OWASP WSTG v4.2
 * checklist. It runs no HTTP probes and launches no scans of its own -
 * scanning stays entirely inside Burp, where it belongs. All findings
 * come from Burp's OWN Scanner (Active Scan you launch normally from
 * Target/Proxy, or Live Passive Scanning while you browse). This
 * extension just listens for and imports those issues, and maps each
 * one onto the matching WSTG id(s) so you get one table that tracks the
 * whole checklist against real Burp results.
 *
 * WARNING: only use this against targets you are authorized to test.
 * This extension itself sends no traffic, but the Burp Scanner findings
 * it imports come from real, sometimes intrusive, attack traffic that
 * Burp sent - only run Burp's scans against scope you're authorized to
 * actively test.
 */
public class WstgMapperExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("WSTG Mapper");

        WstgMapperPanel panel = new WstgMapperPanel(api);
        api.userInterface().registerSuiteTab("WSTG Mapper", panel);

        // Subscribe to every issue Burp's own Scanner reports, active or
        // passive, from this point forward - this extension's only source
        // of findings; it runs no probes of its own.
        api.scanner().registerAuditIssueHandler((AuditIssue issue) ->
                SwingUtilities.invokeLater(() -> panel.onNewAuditIssue(issue)));

        api.logging().logToOutput("WSTG Mapper loaded: " + ChecklistData.ITEMS.size() + " checklist items. "
                + "Run scans normally in Burp (Active Scan / Live Passive Scanning); results stream in "
                + "here live and map onto WSTG automatically. Use \"Import Burp Scanner Issues\" any time "
                + "to top up from issues already sitting in Burp (e.g. from before this tab was open).");
    }
}
