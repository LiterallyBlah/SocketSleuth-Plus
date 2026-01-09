import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;
import burp.api.montoya.websocket.Direction;
import socketsleuth.WebSocketInterceptionRulesTableModel;
import socketsleuth.intruder.executors.Sniper;
import socketsleuth.intruder.payloads.models.IPayloadModel;
import socketsleuth.intruder.payloads.payloads.IIntruderPayloadType;
import socketsleuth.intruder.payloads.payloads.Utils;
import websocket.MessageProvider;

import javax.swing.*;
import java.awt.*;

public class JSONRPCValueBruteForcer {
    private final MessageProvider socketProvider;
    private WebSocketMessageEditor messageEditor;
    private IPayloadModel payloadModel;
    private MontoyaApi api;
    private Sniper executor;
    private JPanel container;
    private JPanel payloadContainer;
    private JButton startAttackButton;
    private JTextField msgIdFieldTxt;
    private JButton messageIdSelectButton;
    private JButton messageIdAutoDetectButton;
    private JSpinner minDelaySpinner;
    private JSpinner maxDelaySpinner;

    public JSONRPCValueBruteForcer(MontoyaApi api, WebSocketMessageEditor messageEditor, MessageProvider socketProvider) {
        this.api = api;
        this.messageEditor = messageEditor;
        this.socketProvider = socketProvider;
        this.minDelaySpinner.getModel().setValue(100);
        this.maxDelaySpinner.getModel().setValue(200);

        // Payload insertion point setup
        this.addButton.addActionListener(e -> {
            String currentContents = messageEditor.getContents().toString();
            String updatedContents;

            // Check if there's a selection
            java.util.Optional<burp.api.montoya.ui.Selection> selection = messageEditor.selection();
            if (selection.isPresent()) {
                // Wrap the selection with § symbols
                burp.api.montoya.core.Range offsets = selection.get().offsets();
                int startIndex = offsets.startIndexInclusive();
                int endIndex = offsets.endIndexExclusive();
                updatedContents = currentContents.substring(0, startIndex) 
                        + "§" 
                        + currentContents.substring(startIndex, endIndex) 
                        + "§" 
                        + currentContents.substring(endIndex);
            } else {
                // No selection, insert single § at caret position (original behavior)
                int caretPosition = messageEditor.caretPosition();
                updatedContents = currentContents.substring(0, caretPosition) + "§" + currentContents.substring(caretPosition);
            }
            
            messageEditor.setContents(ByteArray.byteArray(updatedContents));

            try {
                java.util.List<String> payloads = Utils.extractPayloadPositions(messageEditor.getContents().toString());
                payloadPositionCount.setText(String.valueOf(payloads.size()));
            } catch (Exception ex) {
                payloadPositionCount.setText("Unmatched payload");
            }
        });

        this.clearButton.addActionListener(e -> {
            String currentContents = messageEditor.getContents().toString();
            String updatedContents = currentContents.replaceAll("§", "");
            messageEditor.setContents(ByteArray.byteArray(updatedContents));
            payloadPositionCount.setText("0");
        });

        this.directionCombo.addItem(WebSocketInterceptionRulesTableModel.Direction.CLIENT_TO_SERVER);
        this.directionCombo.addItem(WebSocketInterceptionRulesTableModel.Direction.SERVER_TO_CLIENT);
        
        // Hide the embedded results panel - results will be shown in a separate window
        this.resultsTabbedPane.setVisible(false);
    }

    public Direction getSelectedDirection() {
        WebSocketInterceptionRulesTableModel.Direction direction = (WebSocketInterceptionRulesTableModel.Direction) directionCombo.getSelectedItem();
        if (direction == WebSocketInterceptionRulesTableModel.Direction.CLIENT_TO_SERVER) {
            return Direction.CLIENT_TO_SERVER;
        } else {
            return Direction.SERVER_TO_CLIENT;
        }
    }

    public JButton getStartAttackButton() {
        return startAttackButton;
    }

    public JSpinner getMinDelaySpinner() {
        return minDelaySpinner;
    }

    public JSpinner getMaxDelaySpinner() {
        return maxDelaySpinner;
    }

    public Sniper getExecutor() {
        return executor;
    }

    public void setPayloadType(IIntruderPayloadType payloadForm) {
        // Create executor without a table model - it will be set when attack starts
        this.executor = new Sniper(this.api, this.socketProvider);
        this.payloadModel = payloadForm.getPayloadModel();
        this.setPayloadTypeContainerPanel(payloadForm.getContainer());
    }

    public void setPayloadTypeContainerPanel(JPanel payloadContainer) {
        this.payloadTypeContainer.removeAll();
        this.payloadTypeContainer.add(payloadContainer);
        this.payloadTypeContainer.revalidate();
        this.payloadTypeContainer.repaint();
    }

    private JComboBox payloadTypeCombo;
    private JPanel payloadTypeContainer;
    private JTabbedPane resultsTabbedPane;
    private JButton addButton;
    private JButton clearButton;
    private JCheckBox useReqIDForCheckBox;
    private JLabel payloadPositionCount;
    private JComboBox directionCombo;

    public JPanel getContainer() {
        return container;
    }

    public JPanel getPayloadContainer() {
        return payloadContainer;
    }

    public JComboBox getPayloadTypeCombo() {
        return payloadTypeCombo;
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
        container.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(6, 3, new Insets(0, 0, 0, 0), -1, -1));
        final JLabel label1 = new JLabel();
        label1.setText("Specify JSONRPC payload insertion points");
        container.add(label1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        container.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        payloadContainer = new JPanel();
        payloadContainer.setLayout(new CardLayout(0, 0));
        container.add(payloadContainer, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer2 = new com.intellij.uiDesigner.core.Spacer();
        container.add(spacer2, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(11, 3, new Insets(0, 0, 0, 0), -1, -1));
        container.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        startAttackButton = new JButton();
        startAttackButton.setText("Start Attack");
        panel1.add(startAttackButton, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer3 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer3, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer4 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer4, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Min delay (ms)");
        panel1.add(label2, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Max delay (ms)");
        panel1.add(label3, new com.intellij.uiDesigner.core.GridConstraints(5, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        minDelaySpinner = new JSpinner();
        panel1.add(minDelaySpinner, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        maxDelaySpinner = new JSpinner();
        panel1.add(maxDelaySpinner, new com.intellij.uiDesigner.core.GridConstraints(6, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer5 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer5, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Payload type:");
        panel1.add(label4, new com.intellij.uiDesigner.core.GridConstraints(9, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadTypeCombo = new JComboBox();
        panel1.add(payloadTypeCombo, new com.intellij.uiDesigner.core.GridConstraints(9, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadTypeContainer = new JPanel();
        payloadTypeContainer.setLayout(new CardLayout(0, 0));
        panel1.add(payloadTypeContainer, new com.intellij.uiDesigner.core.GridConstraints(10, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        addButton = new JButton();
        addButton.setText("Add §");
        panel1.add(addButton, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearButton = new JButton();
        clearButton.setText("Clear §");
        panel1.add(clearButton, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Payload positions");
        panel1.add(label5, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadPositionCount = new JLabel();
        payloadPositionCount.setText("0");
        panel1.add(payloadPositionCount, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Direction");
        panel1.add(label6, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        directionCombo = new JComboBox();
        panel1.add(directionCombo, new com.intellij.uiDesigner.core.GridConstraints(8, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer6 = new com.intellij.uiDesigner.core.Spacer();
        container.add(spacer6, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        resultsTabbedPane = new JTabbedPane();
        container.add(resultsTabbedPane, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return container;
    }

}
