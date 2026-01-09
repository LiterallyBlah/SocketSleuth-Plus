import javax.swing.table.AbstractTableModel;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class WebSocketStreamTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private List<WebSocketStream> streams = new ArrayList<>();
    private String[] columns = { "Message ID", "Message", "Direction", "Length", "Time", "Comment" };
    private Class<?>[] columnTypes = { Integer.class, String.class, String.class, Integer.class, LocalDateTime.class, String.class };

    public void addStream(WebSocketStream stream) {
        int index = streams.size();
        streams.add(stream);
        fireTableRowsInserted(index, index);
    }

    public void removeStream(int row) {
        streams.remove(row);
        fireTableRowsDeleted(row, row);
    }

    public WebSocketStream getStream(int row) {
        return streams.get(row);
    }

    public List<WebSocketStream> getStreams() {
        return streams;
    }

    @Override
    public int getRowCount() {
        return streams.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        WebSocketStream stream = streams.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return stream.getMessageID();
            case 1:
                return stream.getMessage();
            case 2:
                // Return string representation for proper sorting/filtering
                return stream.getDirection() != null ? stream.getDirection().toString() : "";
            case 3:
                return stream.getLength();
            case 4:
                return stream.getTime();
            case 5:
                return stream.getComment();
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        // For now only comment is editable - if this changes use a switch like getValueAt
        if (col == 5 && value instanceof String) {
            WebSocketStream stream = streams.get(row);
            stream.setComment((String) value);
            fireTableCellUpdated(row, col);
        }
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnTypes[columnIndex];
    }
}
