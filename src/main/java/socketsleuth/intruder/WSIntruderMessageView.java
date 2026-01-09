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
import socketsleuth.ui.DirectionCellRenderer;
import socketsleuth.ui.MessageFilterPanel;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import java.awt.*;

public class WSIntruderMessageView {
    private JPanel container;
    private JSplitPane resultSplitPane;
    private JTable messageTable;
    private JScrollPane tableScrollPane;
    private JPanel tableContainer;
    private MessageFilterPanel filterPanel;
    private boolean dividerLocationSet = false;

    private WebSocketMessageEditor messageEditor;

    private JSONRPCMessageTableModel tableModel;

    public WSIntruderMessageView(MontoyaApi api) {
        this.messageEditor = api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY);

        this.tableModel = new JSONRPCMessageTableModel();
        messageTable.setModel(this.tableModel);
        
        // Enable sorting
        messageTable.setAutoCreateRowSorter(true);
        
        // Configure column widths
        configureColumnWidths();
        
        // Add direction cell renderer
        messageTable.getColumnModel().getColumn(2).setCellRenderer(new DirectionCellRenderer());
        
        // Create filter panel and wrap the table
        this.filterPanel = new MessageFilterPanel();
        this.filterPanel.setTargetTable(this.messageTable);
        
        // Create a container panel with filter at top and scrollable table below
        this.tableContainer = new JPanel(new BorderLayout());
        this.tableContainer.add(filterPanel, BorderLayout.NORTH);
        
        // Get the scroll pane from the left component (set by form designer)
        Component leftComponent = resultSplitPane.getLeftComponent();
        if (leftComponent instanceof JScrollPane) {
            this.tableScrollPane = (JScrollPane) leftComponent;
            this.tableContainer.add(tableScrollPane, BorderLayout.CENTER);
            resultSplitPane.setLeftComponent(tableContainer);
        }
        
        resultSplitPane.setRightComponent(this.messageEditor.uiComponent());
        
        // Configure split pane resizing behavior
        resultSplitPane.setResizeWeight(0.6); // Give 60% of extra space to the table
        resultSplitPane.setContinuousLayout(true);
        
        // Set initial divider location after the component is visible
        container.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                if (!dividerLocationSet) {
                    SwingUtilities.invokeLater(() -> {
                        int width = resultSplitPane.getWidth();
                        if (width > 0) {
                            resultSplitPane.setDividerLocation((int)(width * 0.55));
                        }
                        dividerLocationSet = true;
                    });
                }
            }
            
            @Override
            public void ancestorRemoved(AncestorEvent event) {}
            
            @Override
            public void ancestorMoved(AncestorEvent event) {}
        });

        this.messageTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = messageTable.getSelectedRow();
                    if (selectedRow != -1) {
                        // Convert view row to model row for sorted tables
                        int modelRow = messageTable.convertRowIndexToModel(selectedRow);
                        JSONRPCMessageTableModel model = (JSONRPCMessageTableModel) messageTable.getModel();
                        JSONRPCMessage message = model.getMessage(modelRow);
                        messageEditor.setContents(ByteArray.byteArray(message.getMessage()));
                    }
                }
            }
        });
    }
    
    /**
     * Configure default column widths for better display.
     */
    private void configureColumnWidths() {
        // Column indices: 0=ID, 1=Message, 2=Direction, 3=Length, 4=Time, 5=Payload
        TableColumn idColumn = messageTable.getColumnModel().getColumn(0);
        idColumn.setPreferredWidth(60);
        idColumn.setMaxWidth(80);
        
        TableColumn messageColumn = messageTable.getColumnModel().getColumn(1);
        messageColumn.setPreferredWidth(350);
        
        TableColumn directionColumn = messageTable.getColumnModel().getColumn(2);
        directionColumn.setPreferredWidth(80);
        directionColumn.setMaxWidth(100);
        
        TableColumn lengthColumn = messageTable.getColumnModel().getColumn(3);
        lengthColumn.setPreferredWidth(70);
        lengthColumn.setMaxWidth(90);
        
        TableColumn timeColumn = messageTable.getColumnModel().getColumn(4);
        timeColumn.setPreferredWidth(140);
        timeColumn.setMaxWidth(170);
        
        TableColumn payloadColumn = messageTable.getColumnModel().getColumn(5);
        payloadColumn.setPreferredWidth(120);
        payloadColumn.setMaxWidth(200);
    }
    
    public MessageFilterPanel getFilterPanel() {
        return filterPanel;
    }

    public JSONRPCMessageTableModel getTableModel() {
        return tableModel;
    }

    public JPanel getContainer() {
        return container;
    }

    public JSplitPane getResultSplitPane() {
        return resultSplitPane;
    }

    public JTable getMessageTable() {
        return messageTable;
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        container = new JPanel();
        container.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        resultSplitPane = new JSplitPane();
        container.add(resultSplitPane, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        resultSplitPane.setLeftComponent(scrollPane1);
        messageTable = new JTable();
        scrollPane1.setViewportView(messageTable);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return container;
    }
}
