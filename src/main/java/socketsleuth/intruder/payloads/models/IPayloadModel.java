package socketsleuth.intruder.payloads.models;

import java.util.Iterator;

/**
 * IPayloadModel is an interface for different types of payload models.
 * Payload models should return an iterator that returns the next payload
 * to process.
 *
 * @param <T> the type of payload (e.g., String, Numeric)
 */
public interface IPayloadModel<T> extends Iterable<T> {
    /**
     * Returns an iterator to iterate through the payloads.
     *
     * @return an Iterator instance
     */
    @Override
    Iterator<T> iterator();
    
    /**
     * Returns the total number of payloads in this model.
     * Used for progress tracking.
     *
     * @return the number of payloads
     */
    int size();
}
