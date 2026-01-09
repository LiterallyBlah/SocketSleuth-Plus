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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A filter panel that provides text-based filtering for JTable message tables.
 */
public class MessageFilterPanel extends JPanel {
    
    private final JTextField filterField;
    private final JComboBox<String> directionFilter;
    private final JCheckBox regexCheckbox;
    private final JButton clearButton;
    private JTable targetTable;
    private TableRowSorter<? extends TableModel> rowSorter;
    
    // Column indices for filtering
    private int messageColumnIndex = 1;   // Default: Message column
    private int directionColumnIndex = 2; // Default: Direction column
    
    public MessageFilterPanel() {
        setLayout(new FlowLayout(FlowLayout.LEFT, 5, 2));
        
        // Filter label
        add(new JLabel("Filter:"));
        
        // Text filter field
        filterField = new JTextField(20);
        filterField.setToolTipText("Enter text to filter messages (Ctrl+F to focus)");
        add(filterField);
        
        // Direction filter
        directionFilter = new JComboBox<>(new String[]{"All", "→ Outgoing", "← Incoming"});
        directionFilter.setToolTipText("Filter by message direction");
        add(directionFilter);
        
        // Regex checkbox
        regexCheckbox = new JCheckBox("Regex");
        regexCheckbox.setToolTipText("Use regular expression for filtering");
        add(regexCheckbox);
        
        // Clear button
        clearButton = new JButton("Clear");
        clearButton.setToolTipText("Clear filter");
        add(clearButton);
        
        // Setup listeners
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        
        directionFilter.addActionListener(e -> applyFilter());
        regexCheckbox.addActionListener(e -> applyFilter());
        clearButton.addActionListener(e -> clearFilter());
    }
    
    /**
     * Sets the target table for filtering.
     */
    public void setTargetTable(JTable table) {
        this.targetTable = table;
        // Note: Don't capture the rowSorter here as the model may not be set yet.
        // The rowSorter will be fetched lazily in applyFilter().
    }
    
    /**
     * Sets the column indices for filtering.
     */
    public void setColumnIndices(int messageColumn, int directionColumn) {
        this.messageColumnIndex = messageColumn;
        this.directionColumnIndex = directionColumn;
    }
    
    /**
     * Applies the current filter to the table.
     */
    @SuppressWarnings("unchecked")
    private void applyFilter() {
        // Always get the current row sorter from the table to handle model changes
        if (targetTable != null && targetTable.getRowSorter() instanceof TableRowSorter) {
            this.rowSorter = (TableRowSorter<? extends TableModel>) targetTable.getRowSorter();
        }
        
        if (rowSorter == null) {
            return;
        }
        
        String text = filterField.getText().trim();
        String direction = (String) directionFilter.getSelectedItem();
        boolean useRegex = regexCheckbox.isSelected();
        
        // No filters active
        if (text.isEmpty() && "All".equals(direction)) {
            ((TableRowSorter<TableModel>) rowSorter).setRowFilter(null);
            filterField.setBackground(UIManager.getColor("TextField.background"));
            return;
        }
        
        try {
            RowFilter<TableModel, Integer> textFilter = null;
            RowFilter<TableModel, Integer> dirFilter = null;
            
            // Create text filter
            if (!text.isEmpty()) {
                if (useRegex) {
                    textFilter = RowFilter.regexFilter(text, messageColumnIndex);
                } else {
                    textFilter = RowFilter.regexFilter("(?i)" + Pattern.quote(text), messageColumnIndex);
                }
            }
            
            // Create direction filter - now works with string values from the table model
            if (!"All".equals(direction)) {
                String dirPattern = direction.contains("Outgoing") ? "CLIENT_TO_SERVER" : "SERVER_TO_CLIENT";
                dirFilter = RowFilter.regexFilter(dirPattern, directionColumnIndex);
            }
            
            // Combine filters
            RowFilter<TableModel, Integer> combinedFilter;
            if (textFilter != null && dirFilter != null) {
                combinedFilter = RowFilter.andFilter(java.util.Arrays.asList(textFilter, dirFilter));
            } else if (textFilter != null) {
                combinedFilter = textFilter;
            } else {
                combinedFilter = dirFilter;
            }
            
            ((TableRowSorter<TableModel>) rowSorter).setRowFilter(combinedFilter);
            filterField.setBackground(UIManager.getColor("TextField.background"));
            
        } catch (PatternSyntaxException e) {
            // Invalid regex - highlight the field
            filterField.setBackground(new Color(255, 200, 200));
        }
    }
    
    /**
     * Clears all filters.
     */
    @SuppressWarnings("unchecked")
    public void clearFilter() {
        filterField.setText("");
        directionFilter.setSelectedIndex(0);
        regexCheckbox.setSelected(false);
        
        // Get current row sorter
        if (targetTable != null && targetTable.getRowSorter() instanceof TableRowSorter) {
            this.rowSorter = (TableRowSorter<? extends TableModel>) targetTable.getRowSorter();
        }
        
        if (rowSorter != null) {
            ((TableRowSorter<TableModel>) rowSorter).setRowFilter(null);
        }
        filterField.setBackground(UIManager.getColor("TextField.background"));
    }
    
    /**
     * Focuses the filter text field.
     */
    public void focusFilterField() {
        filterField.requestFocusInWindow();
        filterField.selectAll();
    }
    
    public JTextField getFilterField() {
        return filterField;
    }
}

