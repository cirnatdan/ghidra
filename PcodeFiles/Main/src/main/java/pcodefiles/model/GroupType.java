package pcodefiles.model;

public enum GroupType {
    GROUP_TYPE_LIST(0),
    GROUP_TYPE_MAP_2D(1),
    GROUP_TYPE_MAP_3D(2);

    private final int value;

    GroupType(final int newValue) {
        value = newValue;
    }

    public int getValue() {
        return value;
    }
}
