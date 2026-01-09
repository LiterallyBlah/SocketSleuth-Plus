package socketsleuth.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom cell renderer that displays a colored status indicator (dot) instead of checkbox.
 */
public class StatusCellRenderer extends DefaultTableCellRenderer {
    
    private static final Color ACTIVE_COLOR = new Color(0, 180, 0);   // Green
    private static final Color INACTIVE_COLOR = new Color(180, 0, 0); // Red
    
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        
        JLabel label = (JLabel) super.getTableCellRendererComponent(
                table, "", isSelected, hasFocus, row, column);
        
        label.setHorizontalAlignment(SwingConstants.CENTER);
        
        boolean isActive = value instanceof Boolean && (Boolean) value;
        
        // Use Unicode circles for status indicators
        if (isActive) {
            label.setText("●");
            label.setForeground(ACTIVE_COLOR);
            label.setToolTipText("Active");
        } else {
            label.setText("●");
            label.setForeground(INACTIVE_COLOR);
            label.setToolTipText("Closed");
        }
        
        return label;
    }
}

