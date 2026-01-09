package socketsleuth.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Window for displaying WebSocket scan results.
 */
public class WSScannerResultsWindow extends JFrame {

    private final MontoyaApi api;
    private final ScanOrchestrator orchestrator;
    private final ScanFindingTableModel tableModel;

    // UI Components
    private JTable findingsTable;
    private JProgressBar progressBar;
    private JButton cancelButton;
    private JLabel statusLabel;
    private JLabel findingCountLabel;

    // Detail panel components
    private JLabel detailTitleLabel;
    private JLabel detailSeverityLabel;
    private JLabel detailCategoryLabel;
    private JTextArea detailDescriptionArea;
    private JTextArea detailEvidenceArea;
    private JTextArea detailRemediationArea;
    private WebSocketMessageEditor requestEditor;
    private WebSocketMessageEditor responseEditor;

    public WSScannerResultsWindow(MontoyaApi api, ScanOrchestrator orchestrator, String targetInfo) {
        super("WS Scanner Results - " + targetInfo);
        this.api = api;
        this.orchestrator = orchestrator;
        this.tableModel = new ScanFindingTableModel();

        initializeUI();
        setupWindowBehavior();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1300, 800));

        // Top panel with progress
        add(createTopPanel(), BorderLayout.NORTH);

        // Main content - split pane
        add(createMainContent(), BorderLayout.CENTER);

        // Status bar
        add(createStatusBar(), BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
    }

    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(new EmptyBorder(10, 10, 5, 10));

        JPanel progressSection = new JPanel(new BorderLayout(10, 0));

        JLabel progressLabel = new JLabel("Progress:");
        progressSection.add(progressLabel, BorderLayout.WEST);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setValue(0);
        progressSection.add(progressBar, BorderLayout.CENTER);

        cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancelScan());
        progressSection.add(cancelButton, BorderLayout.EAST);

        panel.add(progressSection, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createMainContent() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));

        // Create findings table
        findingsTable = new JTable(tableModel);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configureColumnWidths();

        // Selection listener
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = findingsTable.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = findingsTable.convertRowIndexToModel(selectedRow);
                    ScanFinding finding = tableModel.getFinding(modelRow);
                    displayFindingDetails(finding);
                }
            }
        });

        JScrollPane tableScrollPane = new JScrollPane(findingsTable);
        tableScrollPane.setPreferredSize(new Dimension(500, 300));

        // Create details panel
        JPanel detailsPanel = createDetailsPanel();

        // Split pane - table on left, details on right
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(tableScrollPane);
        splitPane.setRightComponent(detailsPanel);
        splitPane.setResizeWeight(0.4);
        splitPane.setContinuousLayout(true);

        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.4));

        panel.add(splitPane, BorderLayout.CENTER);

        return panel;
    }

    private void configureColumnWidths() {
        TableColumn idColumn = findingsTable.getColumnModel().getColumn(0);
        idColumn.setPreferredWidth(50);
        idColumn.setMaxWidth(60);

        TableColumn severityColumn = findingsTable.getColumnModel().getColumn(1);
        severityColumn.setPreferredWidth(80);
        severityColumn.setMaxWidth(100);

        TableColumn categoryColumn = findingsTable.getColumnModel().getColumn(2);
        categoryColumn.setPreferredWidth(150);
        categoryColumn.setMaxWidth(200);

        TableColumn titleColumn = findingsTable.getColumnModel().getColumn(3);
        titleColumn.setPreferredWidth(300);

        TableColumn urlColumn = findingsTable.getColumnModel().getColumn(4);
        urlColumn.setPreferredWidth(250);
    }

    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBorder(new EmptyBorder(5, 10, 5, 5));

        // Top section - finding info
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(new EmptyBorder(0, 0, 10, 0));

        detailTitleLabel = new JLabel(" ");
        detailTitleLabel.setFont(detailTitleLabel.getFont().deriveFont(Font.BOLD, 14f));
        detailTitleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        infoPanel.add(detailTitleLabel);
        infoPanel.add(Box.createVerticalStrut(5));

        JPanel metaPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        metaPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        detailSeverityLabel = new JLabel(" ");
        detailCategoryLabel = new JLabel(" ");
        metaPanel.add(new JLabel("Severity:"));
        metaPanel.add(detailSeverityLabel);
        metaPanel.add(Box.createHorizontalStrut(20));
        metaPanel.add(new JLabel("Category:"));
        metaPanel.add(detailCategoryLabel);
        infoPanel.add(metaPanel);

        panel.add(infoPanel, BorderLayout.NORTH);

        // Center section - description, evidence, remediation
        JTabbedPane detailTabs = new JTabbedPane();

        // Description tab
        detailDescriptionArea = createTextArea();
        detailTabs.addTab("Description", new JScrollPane(detailDescriptionArea));

        // Evidence tab
        detailEvidenceArea = createTextArea();
        detailTabs.addTab("Evidence", new JScrollPane(detailEvidenceArea));

        // Remediation tab
        detailRemediationArea = createTextArea();
        detailTabs.addTab("Remediation", new JScrollPane(detailRemediationArea));

        // Request tab
        requestEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);
        detailTabs.addTab("Request", requestEditor.uiComponent());

        // Response tab
        responseEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);
        detailTabs.addTab("Response", responseEditor.uiComponent());

        panel.add(detailTabs, BorderLayout.CENTER);

        return panel;
    }

    private JTextArea createTextArea() {
        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return textArea;
    }

    private void displayFindingDetails(ScanFinding finding) {
        if (finding == null) {
            clearDetails();
            return;
        }

        detailTitleLabel.setText(finding.getTitle());
        
        // Color code severity
        detailSeverityLabel.setText(finding.getSeverity().getDisplayName());
        switch (finding.getSeverity()) {
            case CRITICAL:
                detailSeverityLabel.setForeground(new Color(139, 0, 0)); // Dark red
                break;
            case HIGH:
                detailSeverityLabel.setForeground(Color.RED);
                break;
            case MEDIUM:
                detailSeverityLabel.setForeground(Color.ORANGE);
                break;
            case LOW:
                detailSeverityLabel.setForeground(new Color(0, 100, 0)); // Dark green
                break;
            case INFO:
                detailSeverityLabel.setForeground(Color.BLUE);
                break;
        }

        detailCategoryLabel.setText(finding.getCategory().getDisplayName());
        
        detailDescriptionArea.setText(finding.getDescription() != null ? finding.getDescription() : "");
        detailDescriptionArea.setCaretPosition(0);
        
        detailEvidenceArea.setText(finding.getEvidence() != null ? finding.getEvidence() : "");
        detailEvidenceArea.setCaretPosition(0);
        
        detailRemediationArea.setText(finding.getRemediation() != null ? finding.getRemediation() : "");
        detailRemediationArea.setCaretPosition(0);

        if (finding.getRequest() != null && !finding.getRequest().isEmpty()) {
            requestEditor.setContents(ByteArray.byteArray(finding.getRequest()));
        } else {
            requestEditor.setContents(ByteArray.byteArray(""));
        }

        if (finding.getResponse() != null && !finding.getResponse().isEmpty()) {
            responseEditor.setContents(ByteArray.byteArray(finding.getResponse()));
        } else {
            responseEditor.setContents(ByteArray.byteArray(""));
        }
    }

    private void clearDetails() {
        detailTitleLabel.setText(" ");
        detailSeverityLabel.setText(" ");
        detailCategoryLabel.setText(" ");
        detailDescriptionArea.setText("");
        detailEvidenceArea.setText("");
        detailRemediationArea.setText("");
        requestEditor.setContents(ByteArray.byteArray(""));
        responseEditor.setContents(ByteArray.byteArray(""));
    }

    private JPanel createStatusBar() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));

        statusLabel = new JLabel("Scan in progress...");
        panel.add(statusLabel, BorderLayout.WEST);

        findingCountLabel = new JLabel("Findings: 0");
        panel.add(findingCountLabel, BorderLayout.EAST);

        return panel;
    }

    private void setupWindowBehavior() {
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                handleWindowClose();
            }
        });
    }

    private void handleWindowClose() {
        if (orchestrator != null && orchestrator.isRunning()) {
            int result = JOptionPane.showConfirmDialog(
                    this,
                    "Scan is still running. Do you want to cancel it and close the window?",
                    "Cancel Scan?",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );

            if (result == JOptionPane.YES_OPTION) {
                orchestrator.cancel();
                dispose();
            }
        } else {
            dispose();
        }
    }

    private void cancelScan() {
        if (orchestrator != null && orchestrator.isRunning()) {
            orchestrator.cancel();
            cancelButton.setEnabled(false);
            statusLabel.setText("Scan cancelled");
        }
    }

    /**
     * Add a finding to the results.
     */
    public void addFinding(ScanFinding finding) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addFinding(finding);
            updateFindingCount();
        });
    }

    /**
     * Update progress bar.
     */
    public void updateProgress(int current, int total) {
        SwingUtilities.invokeLater(() -> {
            int percent = total > 0 ? (current * 100) / total : 0;
            progressBar.setValue(percent);
            progressBar.setString(current + " / " + total + " checks");
        });
    }

    /**
     * Update status message.
     */
    public void updateStatus(String status) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(status));
    }

    /**
     * Called when scan is complete.
     */
    public void onScanComplete() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(100);
            progressBar.setString("Complete");
            cancelButton.setEnabled(false);
            statusLabel.setText("Scan complete - " + tableModel.getSeveritySummary());
            updateFindingCount();
        });
    }

    private void updateFindingCount() {
        findingCountLabel.setText("Findings: " + tableModel.getRowCount());
    }

    /**
     * Get the table model for external access.
     */
    public ScanFindingTableModel getTableModel() {
        return tableModel;
    }

    /**
     * Show the window.
     */
    public void showWindow() {
        setVisible(true);
        toFront();
    }
}
