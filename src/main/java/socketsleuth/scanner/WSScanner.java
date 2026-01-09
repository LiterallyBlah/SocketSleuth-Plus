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
package socketsleuth.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.websocket.ProxyWebSocket;
import websocket.MessageProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.lang.reflect.Method;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Main scanner tab UI for WebSocket vulnerability scanning.
 */
public class WSScanner {

    private final int tabId;
    private final MontoyaApi api;
    private final Object connectionTableModel;
    private final MessageProvider messageProvider;
    private final ScanOrchestrator orchestrator;

    // UI Components
    private JPanel container;
    private JComboBox<WebSocketTargetItem> targetComboBox;
    private JButton refreshButton;
    private Map<ScanCheckCategory, JCheckBox> categoryCheckboxes;
    private JRadioButton passiveOnlyRadio;
    private JRadioButton activeOnlyRadio;
    private JRadioButton fullScanRadio;
    private JSpinner minDelaySpinner;
    private JSpinner maxDelaySpinner;
    private JButton startScanButton;
    private JButton stopButton;

    // Currently selected connection data
    private WebSocketTargetItem selectedTarget;

    public WSScanner(int tabId, MontoyaApi api, Object connectionTableModel, MessageProvider messageProvider) {
        this.tabId = tabId;
        this.api = api;
        this.connectionTableModel = connectionTableModel;
        this.messageProvider = messageProvider;
        this.orchestrator = new ScanOrchestrator(api);
        this.categoryCheckboxes = new EnumMap<>(ScanCheckCategory.class);

        buildUI();
        refreshTargetList();
    }

    private void buildUI() {
        container = new JPanel(new BorderLayout());
        container.setBorder(new EmptyBorder(20, 20, 20, 20));

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

        contentPanel.add(createTargetSection());
        contentPanel.add(Box.createVerticalStrut(15));
        contentPanel.add(createScanProfileSection());
        contentPanel.add(Box.createVerticalStrut(15));
        contentPanel.add(createConfigurationSection());
        contentPanel.add(Box.createVerticalStrut(15));
        contentPanel.add(createActionsSection());
        contentPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        container.add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createTargetSection() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(createTitledBorder("Target"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));

        JPanel targetRow = new JPanel(new BorderLayout(10, 0));
        
        JLabel targetLabel = new JLabel("WebSocket:");
        targetLabel.setPreferredSize(new Dimension(100, 25));
        targetRow.add(targetLabel, BorderLayout.WEST);

        targetComboBox = new JComboBox<>();
        targetComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value,
                    int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof WebSocketTargetItem) {
                    WebSocketTargetItem item = (WebSocketTargetItem) value;
                    setText(item.getDisplayName());
                    if (!item.isActive()) {
                        setForeground(Color.GRAY);
                    }
                }
                return this;
            }
        });
        targetComboBox.addActionListener(e -> onTargetSelected());
        targetRow.add(targetComboBox, BorderLayout.CENTER);

        refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshTargetList());
        targetRow.add(refreshButton, BorderLayout.EAST);

        panel.add(targetRow, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createScanProfileSection() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(createTitledBorder("Scan Profile"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));

        JPanel categoriesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        for (ScanCheckCategory category : ScanCheckCategory.values()) {
            JCheckBox checkbox = new JCheckBox(category.getDisplayName(), true);
            categoryCheckboxes.put(category, checkbox);
            categoriesPanel.add(checkbox);
        }
        panel.add(categoriesPanel, BorderLayout.NORTH);

        JPanel scanTypePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        scanTypePanel.add(new JLabel("Scan Type:"));

        ButtonGroup scanTypeGroup = new ButtonGroup();
        passiveOnlyRadio = new JRadioButton("Passive Only", true);
        activeOnlyRadio = new JRadioButton("Active Only");
        fullScanRadio = new JRadioButton("Full Scan");

        scanTypeGroup.add(passiveOnlyRadio);
        scanTypeGroup.add(activeOnlyRadio);
        scanTypeGroup.add(fullScanRadio);

        scanTypePanel.add(passiveOnlyRadio);
        scanTypePanel.add(activeOnlyRadio);
        scanTypePanel.add(fullScanRadio);

        panel.add(scanTypePanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createConfigurationSection() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        panel.setBorder(createTitledBorder("Configuration"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));

        panel.add(new JLabel("Min Delay:"));
        minDelaySpinner = new JSpinner(new SpinnerNumberModel(100, 0, 10000, 50));
        minDelaySpinner.setPreferredSize(new Dimension(80, 25));
        panel.add(minDelaySpinner);
        panel.add(new JLabel("ms"));

        panel.add(Box.createHorizontalStrut(20));

        panel.add(new JLabel("Max Delay:"));
        maxDelaySpinner = new JSpinner(new SpinnerNumberModel(500, 0, 10000, 50));
        maxDelaySpinner.setPreferredSize(new Dimension(80, 25));
        panel.add(maxDelaySpinner);
        panel.add(new JLabel("ms"));

        return panel;
    }

    private JPanel createActionsSection() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        panel.setBorder(createTitledBorder("Actions"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));

        startScanButton = new JButton("Start Scan");
        startScanButton.setPreferredSize(new Dimension(120, 30));
        startScanButton.addActionListener(e -> startScan());
        panel.add(startScanButton);

        stopButton = new JButton("Stop");
        stopButton.setPreferredSize(new Dimension(80, 30));
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopScan());
        panel.add(stopButton);

        return panel;
    }

    private TitledBorder createTitledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), title);
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD));
        return border;
    }

    private void refreshTargetList() {
        targetComboBox.removeAllItems();
        targetComboBox.addItem(new WebSocketTargetItem(-1, "-- Select a WebSocket --", false, null, null, null));

        try {
            Method getRowCount = connectionTableModel.getClass().getMethod("getRowCount");
            Method getConnection = connectionTableModel.getClass().getMethod("getConnection", int.class);
            
            int rowCount = (int) getRowCount.invoke(connectionTableModel);
            
            for (int i = 0; i < rowCount; i++) {
                Object row = getConnection.invoke(connectionTableModel, i);
                
                // Extract data from WebsocketConnectionTableRow via reflection
                int socketId = (int) row.getClass().getMethod("getSocketId").invoke(row);
                String url = (String) row.getClass().getMethod("getUrl").invoke(row);
                boolean active = (boolean) row.getClass().getMethod("isActive").invoke(row);
                Object streamModel = row.getClass().getMethod("getStreamModel").invoke(row);
                Object proxyWebSocket = row.getClass().getMethod("getProxyWebSocket").invoke(row);
                Object upgradeRequest = row.getClass().getMethod("getUpgradeRequest").invoke(row);
                
                targetComboBox.addItem(new WebSocketTargetItem(socketId, url, active, streamModel, proxyWebSocket, upgradeRequest));
            }
        } catch (Exception e) {
            api.logging().logToError("[WSScanner] Error refreshing target list: " + e.getMessage());
        }
    }

    private void onTargetSelected() {
        selectedTarget = (WebSocketTargetItem) targetComboBox.getSelectedItem();
        if (selectedTarget != null && selectedTarget.getSocketId() >= 0) {
            api.logging().logToOutput("[WSScanner] Selected target: " + selectedTarget.getUrl());
        }
    }

    private void startScan() {
        if (selectedTarget == null || selectedTarget.getSocketId() < 0) {
            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Please select a WebSocket target first.",
                    "No Target Selected",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        if (orchestrator.isRunning()) {
            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "A scan is already in progress.",
                    "Scan In Progress",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        Set<ScanCheckCategory> enabledCategories = EnumSet.noneOf(ScanCheckCategory.class);
        for (Map.Entry<ScanCheckCategory, JCheckBox> entry : categoryCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                enabledCategories.add(entry.getKey());
            }
        }

        if (enabledCategories.isEmpty()) {
            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Please select at least one scan category.",
                    "No Categories Selected",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        boolean passiveOnly = passiveOnlyRadio.isSelected();
        boolean activeMode = activeOnlyRadio.isSelected() || fullScanRadio.isSelected();

        // Build scan context
        ScanContext.Builder contextBuilder = new ScanContext.Builder()
                .api(api)
                .socketId(selectedTarget.getSocketId())
                .url(selectedTarget.getUrl())
                .streamModel(selectedTarget.getStreamModel())
                .messageProvider(messageProvider)
                .activeMode(activeMode);

        // Handle upgrade request (cast if not null)
        if (selectedTarget.getUpgradeRequest() instanceof HttpRequest) {
            contextBuilder.upgradeRequest((HttpRequest) selectedTarget.getUpgradeRequest());
        }

        // Handle proxy websocket (cast if not null)
        if (selectedTarget.getProxyWebSocket() instanceof ProxyWebSocket) {
            contextBuilder.proxyWebSocket((ProxyWebSocket) selectedTarget.getProxyWebSocket());
        }

        ScanContext context = contextBuilder.build();

        // Create and show results window
        String targetInfo = "Socket " + selectedTarget.getSocketId() + " - " + selectedTarget.getUrl();
        WSScannerResultsWindow resultsWindow = new WSScannerResultsWindow(api, orchestrator, targetInfo);

        // Wire up callbacks
        orchestrator.setFindingCallback(resultsWindow::addFinding);
        orchestrator.setProgressCallback(resultsWindow::updateProgress);
        orchestrator.setStatusCallback(resultsWindow::updateStatus);

        // Update UI state
        startScanButton.setEnabled(false);
        stopButton.setEnabled(true);

        // Set completion callback
        orchestrator.setCompletionCallback(() -> {
            SwingUtilities.invokeLater(() -> {
                startScanButton.setEnabled(true);
                stopButton.setEnabled(false);
                resultsWindow.onScanComplete();
            });
        });

        // Show results window and start scan
        resultsWindow.showWindow();
        orchestrator.startScan(context, enabledCategories, passiveOnly);
    }

    private void stopScan() {
        orchestrator.cancel();
        startScanButton.setEnabled(true);
        stopButton.setEnabled(false);
    }

    public JPanel getContainer() {
        return container;
    }

    public void handleData(Object data) {
        // Could handle data passed when opening from context menu
        refreshTargetList();
    }

    /**
     * Wrapper class for WebSocket connection data.
     */
    private static class WebSocketTargetItem {
        private final int socketId;
        private final String url;
        private final boolean active;
        private final Object streamModel;
        private final Object proxyWebSocket;
        private final Object upgradeRequest;

        public WebSocketTargetItem(int socketId, String url, boolean active, 
                Object streamModel, Object proxyWebSocket, Object upgradeRequest) {
            this.socketId = socketId;
            this.url = url;
            this.active = active;
            this.streamModel = streamModel;
            this.proxyWebSocket = proxyWebSocket;
            this.upgradeRequest = upgradeRequest;
        }

        public int getSocketId() {
            return socketId;
        }

        public String getUrl() {
            return url;
        }

        public boolean isActive() {
            return active;
        }

        public Object getStreamModel() {
            return streamModel;
        }

        public Object getProxyWebSocket() {
            return proxyWebSocket;
        }

        public Object getUpgradeRequest() {
            return upgradeRequest;
        }

        public String getDisplayName() {
            if (socketId < 0) {
                return url;
            }
            String status = active ? "[Active]" : "[Closed]";
            return String.format("%s ID: %d - %s", status, socketId, url);
        }

        @Override
        public String toString() {
            return getDisplayName();
        }
    }
}
