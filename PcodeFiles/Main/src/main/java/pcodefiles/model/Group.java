package pcodefiles.model;

import ghidra.program.model.address.Address;

public class Group {
    protected String id;
    String name;
    String address;
    enum DataOrg {
        eByte,
        eLoHi, eHiLo,
        eLoHiLoHi, eHiloHilo,
        eFloatLoHi, eFloatHiLo
    }
    DataOrg dataOrg;
    enum GroupType {
        GROUP_TYPE_LIST,
        GROUP_TYPE_MAP_2D,
        GROUP_TYPE_MAP_3D
    }
    GroupType type;
    int size;

    public Group(String id, String name, String address, String dataOrg, int type, int size) {
        this.id = id;
        this.name = name;
        this.address = address;
        this.size = size;

        switch (dataOrg) {
            case "eByte":
                this.dataOrg = DataOrg.eByte;
                break;
            case "eLoHi":
                this.dataOrg = DataOrg.eLoHi;
                break;
            case "eHiLo":
                this.dataOrg = DataOrg.eHiLo;
                break;
            case "eLoHiLoHi":
                this.dataOrg = DataOrg.eLoHiLoHi;
                break;
            case "eHiLoHilo":
                this.dataOrg = DataOrg.eHiloHilo;
                break;
            case "eFloatLoHi":
                this.dataOrg = DataOrg.eFloatLoHi;
                break;
            case "eFloatHiLo":
                this.dataOrg = DataOrg.eFloatHiLo;
                break;
        }
        switch (type) {
            case 0:
                this.type = GroupType.GROUP_TYPE_LIST;
                break;
            case 1:
                this.type = GroupType.GROUP_TYPE_MAP_2D;
                break;
            case 2:
                this.type = GroupType.GROUP_TYPE_MAP_3D;
                break;

        }
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getAddress() {
        return address;
    }

    public DataOrg getDataOrg() {
        return dataOrg;
    }

    public GroupType getType() {
        return type;
    }

    public int getSize() {
        return size;
    }

    public static Group unserialize(String[] data) {
        return new Group(
                data[0],
                data[1],
                "",
                data[3],
                Integer.parseInt(data[2]),
                Integer.parseInt(data[5])
        );
    }
}
