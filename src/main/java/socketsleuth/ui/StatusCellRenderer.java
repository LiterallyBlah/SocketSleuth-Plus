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

