package socketsleuth.scanner;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Table model for displaying selectable WebSocket messages.
 */
public class MessageTemplateTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {"", "#", "Direction", "Preview"};
    private final List<MessageTemplateRow> rows = new ArrayList<>();
    private final Set<Integer> selectedIndices = new HashSet<>();

    /**
     * Represents a row in the message template table.
     */
    public static class MessageTemplateRow {
        private final int messageId;
        private final String direction;
        private final String content;
        private final String preview;

        public MessageTemplateRow(int messageId, String direction, String content) {
            this.messageId = messageId;
            this.direction = direction;
            this.content = content;
            this.preview = truncate(content, 60);
        }

        private static String truncate(String s, int maxLen) {
            if (s == null) return "";
            s = s.replace("\n", " ").replace("\r", "");
            return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
        }

        public int getMessageId() { return messageId; }
        public String getDirection() { return direction; }
        public String getContent() { return content; }
        public String getPreview() { return preview; }
    }

    /**
     * Clears all rows and selection.
     */
    public void clear() {
        rows.clear();
        selectedIndices.clear();
        fireTableDataChanged();
    }

    /**
     * Adds a row to the table.
     */
    public void addRow(MessageTemplateRow row) {
        rows.add(row);
        fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
    }

    /**
     * Sets the selection state for a row.
     */
    public void setSelected(int rowIndex, boolean selected) {
        if (selected) {
            selectedIndices.add(rowIndex);
        } else {
            selectedIndices.remove(rowIndex);
        }
        fireTableCellUpdated(rowIndex, 0);
    }

    /**
     * Checks if a row is selected.
     */
    public boolean isSelected(int rowIndex) {
        return selectedIndices.contains(rowIndex);
    }

    /**
     * Selects all rows.
     */
    public void selectAll() {
        for (int i = 0; i < rows.size(); i++) {
            selectedIndices.add(i);
        }
        fireTableDataChanged();
    }

    /**
     * Clears all selection.
     */
    public void clearSelection() {
        selectedIndices.clear();
        fireTableDataChanged();
    }

    /**
     * Returns the content of all selected messages.
     */
    public List<String> getSelectedMessages() {
        List<String> selected = new ArrayList<>();
        for (int i : selectedIndices) {
            if (i < rows.size()) {
                selected.add(rows.get(i).getContent());
            }
        }
        return selected;
    }

    @Override
    public int getRowCount() { 
        return rows.size(); 
    }

    @Override
    public int getColumnCount() { 
        return COLUMNS.length; 
    }

    @Override
    public String getColumnName(int col) { 
        return COLUMNS[col]; 
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return col == 0 ? Boolean.class : String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 0; // Only checkbox is editable
    }

    @Override
    public Object getValueAt(int row, int col) {
        MessageTemplateRow r = rows.get(row);
        switch (col) {
            case 0: return selectedIndices.contains(row);
            case 1: return r.getMessageId();
            case 2: return r.getDirection();
            case 3: return r.getPreview();
            default: return null;
        }
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if (col == 0 && value instanceof Boolean) {
            setSelected(row, (Boolean) value);
        }
    }
}
