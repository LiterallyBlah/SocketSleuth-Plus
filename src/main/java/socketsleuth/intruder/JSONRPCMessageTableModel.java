package socketsleuth.intruder;

import burp.api.montoya.websocket.Direction;

import javax.swing.table.AbstractTableModel;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

class JSONRPCMessage {
    private int id;
    private String message;
    private Direction direction;
    private LocalDateTime time;
    private String payload;  // The payload that triggered this message (for grouping)

    public JSONRPCMessage(int id, String message, Direction direction, LocalDateTime time) {
        this(id, message, direction, time, null);
    }
    
    public JSONRPCMessage(int id, String message, Direction direction, LocalDateTime time, String payload) {
        this.id = id;
        this.message = message;
        this.direction = direction;
        this.time = time;
        this.payload = payload;
    }

    public int getId() {
        return id;
    }

    public String getMessage() {
        return message;
    }

    public String getMessagePreview() {
        return message;
    }

    public Direction getDirection() {
        return direction;
    }

    public LocalDateTime getTime() {
        return time;
    }

    public int getLength() {
        return message.length();
    }
    
    public String getPayload() {
        return payload;
    }
}

public class JSONRPCMessageTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private List<JSONRPCMessage> streams = new ArrayList<>();
    private String[] columns = { "Message ID", "Message", "Direction", "Length", "Time", "Payload" };
    private Class<?>[] columnTypes = { Integer.class, String.class, String.class, Integer.class, LocalDateTime.class, String.class };

    /**
     * Add a message without payload tracking (for backwards compatibility).
     */
    public void addMessage(String message, Direction direction) {
        addMessage(message, direction, null);
    }
    
    /**
     * Add a message with payload tracking for request/response grouping.
     * @param message The message content
     * @param direction The direction of the message
     * @param payload The payload that triggered this message (null for responses)
     */
    public void addMessage(String message, Direction direction, String payload) {
        int index = streams.size();
        streams.add(new JSONRPCMessage(
                index,
                message,
                direction,
                LocalDateTime.now(),
                payload
        ));
        fireTableRowsInserted(index, index);
    }

    public void removeMessage(int row) {
        streams.remove(row);
        fireTableRowsDeleted(row, row);
    }

    public JSONRPCMessage getMessage(int row) {
        return streams.get(row);
    }

    public List<JSONRPCMessage> getMessages() {
        return streams;
    }
    
    /**
     * Clear all messages from the table.
     */
    public void clear() {
        int size = streams.size();
        if (size > 0) {
            streams.clear();
            fireTableRowsDeleted(0, size - 1);
        }
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
    public Object getValueAt(int rowIndex, int columnIndex) {
        JSONRPCMessage stream = streams.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return stream.getId();
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
                return stream.getPayload() != null ? stream.getPayload() : "";
            default:
                return null;
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
