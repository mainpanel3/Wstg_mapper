package dev.wstgmapper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

/**
 * The extension's Suite tab UI. Runs no HTTP probes and launches no
 * scans of its own - scanning stays entirely inside Burp. Findings come
 * from Burp's own Scanner: audit issues stream in live via the handler
 * registered in {@link WstgMapperExtension}, and "Import Burp Scanner
 * Issues" is a manual, idempotent top-up for anything already sitting in
 * Burp's issue list (e.g. from before this tab was open).
 */
public final class WstgMapperPanel extends JPanel {

    private final MontoyaApi api;
    private final FindingsStore store = new FindingsStore();
    private final List<String> visibleIds = new ArrayList<>();

    private JComboBox<String> categoryCombo;
    private JTextField searchField;
    private JTable table;
    private DefaultTableModel model;
    private JTextArea detailArea;
    private JLabel statusLabel;

    public WstgMapperPanel(MontoyaApi api) {
        super(new BorderLayout(8, 8));
        this.api = api;
        buildUi();
    }

    // -------------------- UI construction --------------------

    private void buildUi() {
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JButton importButton = new JButton("Import Burp Scanner Issues");
        JButton exportButton = new JButton("Export HTML");
        JButton resetButton = new JButton("Reset All");
        categoryCombo = new JComboBox<>();
        searchField = new JTextField();
        statusLabel = new JLabel(" ");

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JPanel row1 = new JPanel(new BorderLayout(6, 6));
        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        filters.add(new JLabel("Category:"));
        filters.add(categoryCombo);
        filters.add(new JLabel("Search:"));
        searchField.setColumns(20);
        filters.add(searchField);
        row1.add(filters, BorderLayout.WEST);

        JPanel actionButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        actionButtons.add(importButton);
        actionButtons.add(exportButton);
        actionButtons.add(resetButton);
        row1.add(actionButtons, BorderLayout.EAST);

        JPanel row2 = new JPanel(new BorderLayout(6, 6));
        row2.add(statusLabel, BorderLayout.EAST);

        top.add(row1);
        top.add(new JLabel(" "));
        top.add(row2);

        importButton.addActionListener(e -> importScannerIssues());
        exportButton.addActionListener(e -> ReportExporter.export(this, store));
        resetButton.addActionListener(e -> resetAll());
        categoryCombo.addActionListener(e -> refreshTable());
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                refreshTable();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                refreshTable();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                refreshTable();
            }
        });

        String[] columns = {"WSTG ID", "Category", "Title", "Tool", "Type", "Status"};
        model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        table = new JTable(model);
        table.setRowHeight(22);
        table.setAutoCreateRowSorter(true);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetail();
            }
        });
        table.getColumnModel().getColumn(5).setCellRenderer(new SeverityRenderer());
        JScrollPane tableScroll = new JScrollPane(table);

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setPreferredSize(new Dimension(100, 180));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.72);

        add(top, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        categoryCombo.addItem(ChecklistData.ALL_CATEGORIES_LABEL);
        for (String c : ChecklistData.CATEGORY_ORDER) {
            categoryCombo.addItem(c);
        }

        statusLabel.setText(ChecklistData.ITEMS.size() + " WSTG items loaded. Run scans in Burp as "
                + "usual - results stream in here live.");
        refreshTable();
    }

    private final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public java.awt.Component getTableCellRendererComponent(JTable tbl, Object value, boolean isSelected,
                                                                  boolean hasFocus, int row, int col) {
            var c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, col);
            try {
                int modelRow = tbl.convertRowIndexToModel(row);
                String wid = visibleIds.get(modelRow);
                Severity sev = store.get(wid).severity();
                if (!isSelected) {
                    Color bg = sev.color();
                    c.setBackground(bg);
                    double lum = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255.0;
                    c.setForeground(lum > 0.6 ? Color.BLACK : Color.WHITE);
                }
                ((javax.swing.JComponent) c).setOpaque(true);
            } catch (Exception ignored) {
                // leave default rendering
            }
            return c;
        }
    }

    // -------------------- table / filter --------------------

    private void refreshTable() {
        Object category = categoryCombo.getSelectedItem();
        String needle = searchField.getText();
        needle = needle == null ? "" : needle.trim().toLowerCase();

        model.setRowCount(0);
        visibleIds.clear();
        for (ChecklistItem item : ChecklistData.ITEMS) {
            String wid = item.id();
            boolean catOk = category == null || ChecklistData.ALL_CATEGORIES_LABEL.equals(category)
                    || item.category().equals(category);
            Finding f = store.get(wid);
            boolean textOk = needle.isEmpty()
                    || wid.toLowerCase().contains(needle)
                    || item.title().toLowerCase().contains(needle)
                    || f.guidance().toLowerCase().contains(needle);
            if (catOk && textOk) {
                boolean hasScanner = f.hasScannerIssues();
                String rowType = hasScanner ? "Manual + Burp Scanner" : "Manual (not covered by Burp yet)";
                model.addRow(new Object[]{wid, item.category(), item.title(), item.tool(), rowType,
                        f.severity().label()});
                visibleIds.add(wid);
            }
        }
    }

    private void showSelectedDetail() {
        int row = table.getSelectedRow();
        if (row < 0) {
            detailArea.setText("");
            return;
        }
        int modelRow = table.convertRowIndexToModel(row);
        String wid = visibleIds.get(modelRow);
        ChecklistItem item = ChecklistData.BY_ID.get(wid);
        Finding f = store.get(wid);
        boolean hasScanner = f.hasScannerIssues();

        StringBuilder sb = new StringBuilder();
        sb.append(wid).append(" - ").append(item.title()).append('\n');
        sb.append("Category: ").append(item.category()).append('\n');
        sb.append("Suggested Burp tool: ").append(item.tool()).append('\n');
        sb.append("Status: ").append(f.severity().label()).append('\n');
        sb.append("=".repeat(60)).append('\n');
        sb.append("MANUAL TESTING GUIDANCE (do this by hand in Burp / browser):\n\n");
        for (String line : TextUtil.formatGuidance(item.guidance())) {
            sb.append(line).append('\n');
        }
        if (hasScanner) {
            sb.append('\n').append("=".repeat(60)).append('\n');
            sb.append("BURP SCANNER FINDINGS MAPPED TO THIS ITEM (").append(f.scannerIssues().size())
                    .append(") - review these first, they may already answer the manual check above:\n");
            for (String note : f.scannerIssues()) {
                sb.append('\n').append(" - ").append(note).append('\n');
            }
        } else {
            sb.append('\n').append("=".repeat(60)).append('\n');
            sb.append("No Burp Scanner finding has been mapped to this item yet - it still needs to be "
                    + "tested manually (or click \"Import Burp Scanner Issues\" if you already ran a scan "
                    + "and it has not shown up here).\n");
        }
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    // -------------------- Burp Scanner integration --------------------

    /** Called (already on the EDT) for every new audit issue Burp reports, live. */
    public void onNewAuditIssue(AuditIssue issue) {
        store.mergeIssue(issue);
        refreshTable();
        showSelectedDetail();
    }

    /**
     * Pulls every issue from Burp's own site map / issue list and merges it
     * in. Filters by Burp's own Target Scope if one is configured; if not,
     * imports everything rather than silently importing nothing. Idempotent:
     * issues already merged (e.g. picked up live while a scan was running)
     * are recognized and skipped, so a repeated "0 new" result is expected,
     * not a failure.
     */
    private void importScannerIssues() {
        List<AuditIssue> allIssues;
        try {
            allIssues = api.siteMap().issues();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Could not read Burp Scanner issues: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        boolean scopeDefined = false;
        List<Boolean> inScopeFlags = new ArrayList<>();
        for (AuditIssue issue : allIssues) {
            boolean inScope;
            try {
                inScope = api.scope().isInScope(issue.baseUrl());
            } catch (Exception e) {
                inScope = false;
            }
            if (inScope) {
                scopeDefined = true;
            }
            inScopeFlags.add(inScope);
        }

        List<AuditIssue> relevantIssues = new ArrayList<>();
        if (scopeDefined) {
            for (int i = 0; i < allIssues.size(); i++) {
                if (inScopeFlags.get(i)) {
                    relevantIssues.add(allIssues.get(i));
                }
            }
        } else {
            relevantIssues.addAll(allIssues);
        }

        int newCount = 0;
        for (AuditIssue issue : relevantIssues) {
            FindingsStore.MergeResult result = store.mergeIssue(issue);
            if (result == FindingsStore.MergeResult.NEW_MAPPED || result == FindingsStore.MergeResult.NEW_UNMAPPED) {
                newCount++;
            }
        }

        refreshTable();
        int totalUnmappedNow = store.get(ChecklistData.GENERAL_FINDINGS_ID).scannerIssues().size();
        String source = scopeDefined ? "Burp Target Scope" : "all issues Burp currently holds (no Scope set)";
        statusLabel.setText(allIssues.size() + " issue(s) in Burp overall, " + relevantIssues.size()
                + " selected via " + source + " | " + newCount + " newly imported this click ("
                + (relevantIssues.size() - newCount) + " already imported earlier) | " + totalUnmappedNow
                + " unmapped issue(s) total sit in WSTG-GEN-00.");
    }

    /**
     * Wipes every finding back to its initial MANUAL/guidance state and
     * forgets which Burp issues were already merged, so a fresh import (or
     * newly streamed issues) will re-populate the table from scratch. Does
     * not touch Burp's own issue list or Scope - only this local table.
     */
    private void resetAll() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "This clears all mapped findings and Burp Scanner notes from this table "
                        + "(Burp's own issue list is not affected). Continue?",
                "Reset All", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }
        store.reset();
        refreshTable();
        detailArea.setText("");
        statusLabel.setText(ChecklistData.ITEMS.size() + " WSTG items reset. Click \"Import Burp Scanner "
                + "Issues\" to re-pull anything already in Burp, or just keep scanning - live results "
                + "will re-populate the table.");
    }
}
