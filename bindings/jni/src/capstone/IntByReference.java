package capstone;

public class IntByReference {

    private int value = 0;

    public IntByReference() {
        this(0);
    }

    public IntByReference(int value) {
        setValue(value);
    }

    public void setValue(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
