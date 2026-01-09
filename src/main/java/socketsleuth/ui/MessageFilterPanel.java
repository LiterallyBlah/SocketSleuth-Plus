package socketsleuth.ui;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A filter panel that provides text-based filtering for JTable message tables.
 */
public class MessageFilterPanel extends JPanel {
    
    private final JTextField filterField;
    private final JComboBox<String> directionFilter;
    private final JCheckBox regexCheckbox;
    private final JCheckBox uniqueCheckbox;
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
        
        // Unique only checkbox
        uniqueCheckbox = new JCheckBox("Unique Only");
        uniqueCheckbox.setToolTipText("Show only unique messages (first occurrence of each message per direction)");
        add(uniqueCheckbox);
        
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
        uniqueCheckbox.addActionListener(e -> applyFilter());
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
        boolean showUniqueOnly = uniqueCheckbox.isSelected();
        
        // No filters active
        if (text.isEmpty() && "All".equals(direction) && !showUniqueOnly) {
            ((TableRowSorter<TableModel>) rowSorter).setRowFilter(null);
            filterField.setBackground(UIManager.getColor("TextField.background"));
            return;
        }
        
        try {
            List<RowFilter<TableModel, Integer>> filters = new ArrayList<>();
            
            // Create text filter
            if (!text.isEmpty()) {
                if (useRegex) {
                    filters.add(RowFilter.regexFilter(text, messageColumnIndex));
                } else {
                    filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(text), messageColumnIndex));
                }
            }
            
            // Create direction filter - now works with string values from the table model
            if (!"All".equals(direction)) {
                String dirPattern = direction.contains("Outgoing") ? "CLIENT_TO_SERVER" : "SERVER_TO_CLIENT";
                filters.add(RowFilter.regexFilter(dirPattern, directionColumnIndex));
            }
            
            // Create unique filter if enabled
            if (showUniqueOnly) {
                filters.add(createUniqueFilter());
            }
            
            // Combine filters
            RowFilter<TableModel, Integer> combinedFilter;
            if (filters.isEmpty()) {
                combinedFilter = null;
            } else if (filters.size() == 1) {
                combinedFilter = filters.get(0);
            } else {
                combinedFilter = RowFilter.andFilter(filters);
            }
            
            ((TableRowSorter<TableModel>) rowSorter).setRowFilter(combinedFilter);
            filterField.setBackground(UIManager.getColor("TextField.background"));
            
        } catch (PatternSyntaxException e) {
            // Invalid regex - highlight the field
            filterField.setBackground(new Color(255, 200, 200));
        }
    }
    
    /**
     * Creates a filter that shows only the first occurrence of each unique message per direction.
     */
    private RowFilter<TableModel, Integer> createUniqueFilter() {
        // Pre-compute which rows should be shown based on uniqueness
        TableModel model = targetTable.getModel();
        Set<String> seenOutgoing = new HashSet<>();
        Set<String> seenIncoming = new HashSet<>();
        Set<Integer> uniqueRows = new HashSet<>();
        
        for (int i = 0; i < model.getRowCount(); i++) {
            Object messageObj = model.getValueAt(i, messageColumnIndex);
            Object directionObj = model.getValueAt(i, directionColumnIndex);
            
            String message = messageObj != null ? messageObj.toString() : "";
            String dir = directionObj != null ? directionObj.toString() : "";
            
            // Use direction-specific sets to track unique messages
            Set<String> seenSet = dir.contains("CLIENT_TO_SERVER") ? seenOutgoing : seenIncoming;
            
            if (!seenSet.contains(message)) {
                seenSet.add(message);
                uniqueRows.add(i);
            }
        }
        
        final Set<Integer> rowsToShow = uniqueRows;
        
        return new RowFilter<TableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
                return rowsToShow.contains(entry.getIdentifier());
            }
        };
    }
    
    /**
     * Clears all filters.
     */
    @SuppressWarnings("unchecked")
    public void clearFilter() {
        filterField.setText("");
        directionFilter.setSelectedIndex(0);
        regexCheckbox.setSelected(false);
        uniqueCheckbox.setSelected(false);
        
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

