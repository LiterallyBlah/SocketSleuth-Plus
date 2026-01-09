package socketsleuth.intruder.payloads.models;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class NumericPayloadModel implements IPayloadModel<String> {

    private int from;
    private int to;
    private int step;
    private int minDigits;

    public NumericPayloadModel(int from, int to, int step, int minDigits) {
        this.from = from;
        this.to = to;
        this.step = step;
        this.minDigits = minDigits;
    }

    public void setFrom(int from) {
        this.from = from;
    }

    public void setTo(int to) {
        this.to = to;
    }

    public void setStep(int step) {
        this.step = step;
    }

    public void setMinDigits(int minDigits) {
        this.minDigits = minDigits;
    }

    @Override
    public Iterator<String> iterator() {
        return new Iterator<>() {
            int current = from;

            @Override
            public boolean hasNext() {
                return current <= to;
            }

            @Override
            public String next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                String result = formatNumber(current);
                current += step;
                return result;
            }

            private String formatNumber(int number) {
                String format = "%0" + minDigits + "d";
                return String.format(format, number);
            }
        };
    }
    
    /**
     * Returns the total number of payloads in this model.
     *
     * @return the number of payloads
     */
    @Override
    public int size() {
        if (step <= 0) {
            return 0;
        }
        return Math.max(0, (to - from) / step + 1);
    }
}