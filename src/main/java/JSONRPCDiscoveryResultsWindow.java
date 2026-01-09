import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;
import socketsleuth.intruder.JSONRPCMessageTableModel;
import socketsleuth.ui.DirectionCellRenderer;
import socketsleuth.ui.MessageFilterPanel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * A dedicated window for displaying JSONRPC method discovery results.
 * Similar to Burp Suite's Intruder attack window pattern.
 */
public class JSONRPCDiscoveryResultsWindow extends JFrame 
        implements MethodDetectedListener, ResponseReceivedListener {
    
    private final MontoyaApi api;
    private volatile boolean cancelled = false;
    private Thread discoveryThread;
    
    // UI Components
    private JTabbedPane tabbedPane;
    private JProgressBar progressBar;
    private JButton cancelButton;
    private JLabel statusLabel;
    private JLabel methodCountLabel;
    
    // Discovered Methods tab
    private JList<JSONRPCMethodItem> discoveredList;
    private DefaultListModel<JSONRPCMethodItem> discoveredListModel;
    private WebSocketMessageEditor requestEditor;
    private WebSocketMessageEditor responseEditor;
    
    // All Messages tab
    private JTable messageTable;
    private JSONRPCMessageTableModel messageTableModel;
    private WebSocketMessageEditor messageEditor;
    private MessageFilterPanel filterPanel;
    
    public JSONRPCDiscoveryResultsWindow(MontoyaApi api, String websocketInfo) {
        super("JSONRPC Method Discovery - " + websocketInfo);
        this.api = api;
        
        initializeUI();
        setupWindowBehavior();
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 700));
        
        // Top panel with progress and controls
        JPanel topPanel = createTopPanel();
        add(topPanel, BorderLayout.NORTH);
        
        // Tabbed pane for results
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Discovered Methods", createDiscoveredMethodsPanel());
        tabbedPane.addTab("All Messages", createAllMessagesPanel());
        add(tabbedPane, BorderLayout.CENTER);
        
        // Status bar at bottom
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);
        
        pack();
        setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
    }
    
    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(new EmptyBorder(10, 10, 5, 10));
        
        // Progress section
        JPanel progressSection = new JPanel(new BorderLayout(10, 0));
        
        JLabel progressLabel = new JLabel("Progress:");
        progressSection.add(progressLabel, BorderLayout.WEST);
        
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setValue(0);
        progressSection.add(progressBar, BorderLayout.CENTER);
        
        cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancelDiscovery());
        progressSection.add(cancelButton, BorderLayout.EAST);
        
        panel.add(progressSection, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createDiscoveredMethodsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create editors for request/response
        requestEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);
        
        // Create list of discovered methods
        discoveredListModel = new DefaultListModel<>();
        discoveredList = new JList<>(discoveredListModel);
        discoveredList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // Selection listener to update editors
        discoveredList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                JSONRPCMethodItem selectedItem = discoveredList.getSelectedValue();
                if (selectedItem != null) {
                    requestEditor.setContents(ByteArray.byteArray(selectedItem.getRequest()));
                    responseEditor.setContents(ByteArray.byteArray(selectedItem.getResponse()));
                } else {
                    requestEditor.setContents(ByteArray.byteArray(""));
                    responseEditor.setContents(ByteArray.byteArray(""));
                }
            }
        });
        
        // Left panel - discovered methods list
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(new JLabel("Discovered Methods:"), BorderLayout.NORTH);
        leftPanel.add(new JScrollPane(discoveredList), BorderLayout.CENTER);
        
        // Right panel - request/response editors
        JPanel rightPanel = new JPanel(new GridLayout(1, 2, 5, 0));
        
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.add(new JLabel("WS Request"), BorderLayout.NORTH);
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.add(new JLabel("WS Response"), BorderLayout.NORTH);
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        
        rightPanel.add(requestPanel);
        rightPanel.add(responsePanel);
        
        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(rightPanel);
        splitPane.setResizeWeight(0.25);
        splitPane.setContinuousLayout(true);
        
        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.25));
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createAllMessagesPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create message editor
        messageEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);
        
        // Create table
        messageTableModel = new JSONRPCMessageTableModel();
        messageTable = new JTable(messageTableModel);
        messageTable.setAutoCreateRowSorter(true);
        messageTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configureColumnWidths();
        
        // Add direction cell renderer
        messageTable.getColumnModel().getColumn(2).setCellRenderer(new DirectionCellRenderer());
        
        // Selection listener
        messageTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = messageTable.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = messageTable.convertRowIndexToModel(selectedRow);
                    // Get message content from column 1 (Message column)
                    String messageContent = (String) messageTableModel.getValueAt(modelRow, 1);
                    messageEditor.setContents(ByteArray.byteArray(messageContent != null ? messageContent : ""));
                }
            }
        });
        
        // Filter panel
        filterPanel = new MessageFilterPanel();
        filterPanel.setTargetTable(messageTable);
        
        // Table panel with filter
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(filterPanel, BorderLayout.NORTH);
        tablePanel.add(new JScrollPane(messageTable), BorderLayout.CENTER);
        
        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(tablePanel);
        splitPane.setRightComponent(messageEditor.uiComponent());
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);
        
        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void configureColumnWidths() {
        TableColumn idColumn = messageTable.getColumnModel().getColumn(0);
        idColumn.setPreferredWidth(60);
        idColumn.setMaxWidth(80);
        
        TableColumn msgColumn = messageTable.getColumnModel().getColumn(1);
        msgColumn.setPreferredWidth(400);
        
        TableColumn dirColumn = messageTable.getColumnModel().getColumn(2);
        dirColumn.setPreferredWidth(80);
        dirColumn.setMaxWidth(100);
        
        TableColumn lenColumn = messageTable.getColumnModel().getColumn(3);
        lenColumn.setPreferredWidth(70);
        lenColumn.setMaxWidth(90);
        
        TableColumn timeColumn = messageTable.getColumnModel().getColumn(4);
        timeColumn.setPreferredWidth(150);
        timeColumn.setMaxWidth(180);
        
        TableColumn payloadColumn = messageTable.getColumnModel().getColumn(5);
        payloadColumn.setPreferredWidth(150);
        payloadColumn.setMaxWidth(250);
    }
    
    private JPanel createStatusBar() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));
        
        statusLabel = new JLabel("Discovery in progress...");
        panel.add(statusLabel, BorderLayout.WEST);
        
        methodCountLabel = new JLabel("Methods found: 0 | Messages: 0");
        panel.add(methodCountLabel, BorderLayout.EAST);
        
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
        if (!cancelled && discoveryThread != null && discoveryThread.isAlive()) {
            int result = JOptionPane.showConfirmDialog(
                this,
                "Discovery is still running. Do you want to cancel it and close the window?",
                "Cancel Discovery?",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );
            
            if (result == JOptionPane.YES_OPTION) {
                cancelDiscovery();
                dispose();
            }
        } else {
            dispose();
        }
    }
    
    private void cancelDiscovery() {
        cancelled = true;
        if (discoveryThread != null) {
            discoveryThread.interrupt();
        }
        cancelButton.setEnabled(false);
        statusLabel.setText("Discovery cancelled");
    }
    
    /**
     * Set the discovery thread for cancellation support.
     */
    public void setDiscoveryThread(Thread thread) {
        this.discoveryThread = thread;
    }
    
    /**
     * Check if discovery was cancelled.
     */
    public boolean isCancelled() {
        return cancelled;
    }
    
    /**
     * Update the progress bar.
     */
    public void updateProgress(int current, int total) {
        SwingUtilities.invokeLater(() -> {
            int percent = total > 0 ? (current * 100) / total : 0;
            progressBar.setValue(percent);
            updateStatusCounts();
        });
    }
    
    /**
     * Called when discovery is complete.
     */
    public void onDiscoveryComplete() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(100);
            cancelButton.setEnabled(false);
            statusLabel.setText("Discovery complete");
            updateStatusCounts();
        });
    }
    
    private void updateStatusCounts() {
        int methodCount = discoveredListModel.size();
        int messageCount = messageTableModel.getRowCount();
        methodCountLabel.setText("Methods found: " + methodCount + " | Messages: " + messageCount);
    }
    
    /**
     * Show the window.
     */
    public void showWindow() {
        setVisible(true);
        toFront();
    }
    
    // MethodDetectedListener implementation
    @Override
    public void onMethodDetected(MethodDetectedEvent event) {
        SwingUtilities.invokeLater(() -> {
            api.logging().logToOutput("Method discovered: " + event.getMethodName());
            discoveredListModel.addElement(new JSONRPCMethodItem(
                    event.getMethodName(), 
                    event.getRequest().getRequest().toString(), 
                    event.getResponse()
            ));
            updateStatusCounts();
        });
    }
    
    // ResponseReceivedListener implementation
    @Override
    public void onResponseReceived(MessageEvent event) {
        SwingUtilities.invokeLater(() -> {
            messageTableModel.addMessage(event.getMessage(), event.getDirection());
            updateStatusCounts();
        });
    }
}
