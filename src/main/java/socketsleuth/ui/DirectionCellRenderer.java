package socketsleuth.ui;

import burp.api.montoya.websocket.Direction;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom cell renderer that displays direction arrows instead of text.
 */
public class DirectionCellRenderer extends DefaultTableCellRenderer {
    
    private static final Color OUTGOING_COLOR = new Color(0, 120, 200);   // Blue
    private static final Color INCOMING_COLOR = new Color(200, 120, 0);   // Orange
    
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        
        JLabel label = (JLabel) super.getTableCellRendererComponent(
                table, "", isSelected, hasFocus, row, column);
        
        label.setHorizontalAlignment(SwingConstants.CENTER);
        
        if (value == null) {
            label.setText("");
            return label;
        }
        
        String directionStr = value.toString();
        
        if (directionStr.contains("CLIENT_TO_SERVER") || 
            directionStr.equals(Direction.CLIENT_TO_SERVER.toString())) {
            label.setText("→");
            label.setForeground(OUTGOING_COLOR);
            label.setToolTipText("Client → Server (Outgoing)");
        } else if (directionStr.contains("SERVER_TO_CLIENT") || 
                   directionStr.equals(Direction.SERVER_TO_CLIENT.toString())) {
            label.setText("←");
            label.setForeground(INCOMING_COLOR);
            label.setToolTipText("Server → Client (Incoming)");
        } else {
            label.setText("↔");
            label.setToolTipText("Bidirectional");
        }
        
        // Use a slightly larger font for arrows
        Font currentFont = label.getFont();
        label.setFont(currentFont.deriveFont(currentFont.getSize() * 1.2f));
        
        return label;
    }
}

