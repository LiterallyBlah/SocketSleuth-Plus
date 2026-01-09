package socketsleuth.intruder.payloads.models;

import javax.swing.*;
import java.util.HashSet;
import java.util.Iterator;

/**
 * StringPayloadModel is a concrete implementation of IPayloadModel for
 * a basic list of String payloads.
 */
public class StringPayloadModel implements IPayloadModel<String> {

    private final DefaultListModel<String> listModel;

    public StringPayloadModel() {
        this.listModel = new DefaultListModel<>();
    }

    /**
     * Adds a new String payload to the model.
     *
     * @param payload the String payload to add
     */
    public void addPayload(String payload) {
        listModel.addElement(payload);
    }

    /**
     * Removes a String payload from the model by its index.
     *
     * @param index the index of the String payload to remove
     */
    public void removePayload(int index) {
        listModel.remove(index);
    }

    /**
     * Removes duplicate String payloads from the model.
     */
    public void removeDuplicates() {
        HashSet<String> seen = new HashSet<>();
        for (int i = listModel.size() - 1; i >= 0; i--) {
            String payload = listModel.get(i);
            if (seen.contains(payload)) {
                listModel.remove(i);
            } else {
                seen.add(payload);
            }
        }
    }

    /**
     * Returns an iterator to iterate through the String payloads.
     *
     * @return an Iterator<String> instance
     */
    @Override
    public Iterator<String> iterator() {
        return listModel.elements().asIterator();
    }

    /**
     * Returns the underlying list model used to store the list of string payloads.
     *
     * @return a DefaultListModel<String> instance
     */
    public DefaultListModel<String> getListModel() {
        return this.listModel;
    }
    
    /**
     * Returns the total number of payloads in this model.
     *
     * @return the number of payloads
     */
    @Override
    public int size() {
        return listModel.size();
    }
}
