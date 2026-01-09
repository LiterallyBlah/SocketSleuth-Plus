/*
 * © 2023 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package socketsleuth.intruder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;
import socketsleuth.intruder.executors.Sniper;
import socketsleuth.ui.DirectionCellRenderer;
import socketsleuth.ui.MessageFilterPanel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * A dedicated window for displaying WS Intruder attack results.
 * Similar to Burp Suite's Intruder attack window pattern.
 */
public class WSIntruderResultsWindow extends JFrame {
    
    private final MontoyaApi api;
    private final Sniper executor;
    private final JSONRPCMessageTableModel tableModel;
    
    // UI Components
    private JTable messageTable;
    private WebSocketMessageEditor messageEditor;
    private MessageFilterPanel filterPanel;
    private JSplitPane splitPane;
    private JProgressBar progressBar;
    private JButton cancelButton;
    private JLabel statusLabel;
    private JLabel requestCountLabel;
    
    public WSIntruderResultsWindow(MontoyaApi api, Sniper executor, String websocketInfo) {
        super("WS Intruder Attack - " + websocketInfo);
        this.api = api;
        this.executor = executor;
        this.tableModel = new JSONRPCMessageTableModel();
        
        initializeUI();
        setupWindowBehavior();
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 700));
        
        // Top panel with progress and controls
        JPanel topPanel = createTopPanel();
        add(topPanel, BorderLayout.NORTH);
        
        // Main content - split pane with table and message viewer
        JPanel mainContent = createMainContent();
        add(mainContent, BorderLayout.CENTER);
        
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
        cancelButton.addActionListener(e -> cancelAttack());
        progressSection.add(cancelButton, BorderLayout.EAST);
        
        panel.add(progressSection, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createMainContent() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));
        
        // Create the message editor
        messageEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);
        
        // Create the table
        messageTable = new JTable(tableModel);
        messageTable.setAutoCreateRowSorter(true);
        messageTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configureColumnWidths();
        
        // Add direction cell renderer
        messageTable.getColumnModel().getColumn(2).setCellRenderer(new DirectionCellRenderer());
        
        // Selection listener to update message editor
        messageTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = messageTable.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = messageTable.convertRowIndexToModel(selectedRow);
                    JSONRPCMessage message = tableModel.getMessage(modelRow);
                    messageEditor.setContents(ByteArray.byteArray(message.getMessage()));
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
        
        // Split pane - table on left, message viewer on right
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(tablePanel);
        splitPane.setRightComponent(messageEditor.uiComponent());
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);
        
        // Set initial divider location after visible
        SwingUtilities.invokeLater(() -> {
            splitPane.setDividerLocation(0.5);
        });
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void configureColumnWidths() {
        // Column indices: 0=ID, 1=Message, 2=Direction, 3=Length, 4=Time, 5=Payload
        TableColumn idColumn = messageTable.getColumnModel().getColumn(0);
        idColumn.setPreferredWidth(60);
        idColumn.setMaxWidth(80);
        
        TableColumn messageColumn = messageTable.getColumnModel().getColumn(1);
        messageColumn.setPreferredWidth(400);
        
        TableColumn directionColumn = messageTable.getColumnModel().getColumn(2);
        directionColumn.setPreferredWidth(80);
        directionColumn.setMaxWidth(100);
        
        TableColumn lengthColumn = messageTable.getColumnModel().getColumn(3);
        lengthColumn.setPreferredWidth(70);
        lengthColumn.setMaxWidth(90);
        
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
        
        statusLabel = new JLabel("Attack in progress...");
        panel.add(statusLabel, BorderLayout.WEST);
        
        requestCountLabel = new JLabel("Requests: 0");
        panel.add(requestCountLabel, BorderLayout.EAST);
        
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
        if (executor != null && executor.isRunning()) {
            int result = JOptionPane.showConfirmDialog(
                this,
                "Attack is still running. Do you want to cancel it and close the window?",
                "Cancel Attack?",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );
            
            if (result == JOptionPane.YES_OPTION) {
                executor.cancel();
                dispose();
            }
        } else {
            dispose();
        }
    }
    
    private void cancelAttack() {
        if (executor != null && executor.isRunning()) {
            executor.cancel();
            cancelButton.setEnabled(false);
            statusLabel.setText("Attack cancelled");
        }
    }
    
    /**
     * Get the table model to add messages during the attack.
     */
    public JSONRPCMessageTableModel getTableModel() {
        return tableModel;
    }
    
    /**
     * Update the progress bar.
     */
    public void updateProgress(int percent) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(percent);
            requestCountLabel.setText("Requests: " + tableModel.getRowCount());
        });
    }
    
    /**
     * Called when the attack is complete.
     */
    public void onAttackComplete() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(100);
            cancelButton.setEnabled(false);
            statusLabel.setText("Attack complete - " + tableModel.getRowCount() + " messages");
            requestCountLabel.setText("Requests: " + tableModel.getRowCount());
        });
    }
    
    /**
     * Show the window and start displaying results.
     */
    public void showWindow() {
        setVisible(true);
        toFront();
    }
}
