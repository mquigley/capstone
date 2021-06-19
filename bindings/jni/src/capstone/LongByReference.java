package capstone;

public class LongByReference {

    private long value = 0;

    public LongByReference() {
        this(0);
    }

    public LongByReference(int value) {
        setValue(value);
    }

    public void setValue(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "" + value;
    }
}
