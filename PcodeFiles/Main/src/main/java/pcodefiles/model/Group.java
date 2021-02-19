package pcodefiles.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddress;

import java.util.HashMap;
import java.util.Map;

public class Group {
    protected String id;
    String name;
    Address address;
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
    int x;
    int y;

    public String getFolderName() {
        return folderName;
    }

    public void setFolderName(String folderName) {
        this.folderName = folderName;
    }

    String folderName;

    public Group(String id) {
        this.id = id;
    }

    public Group(String id, String name, Address address, String dataOrg, int type, int length) {
        this.id = id;
        this.name = name;
        this.address = address;
        this.y = length;

        this.type = intToType(type);
        this.dataOrg = stringToDataOrg(dataOrg);
    }

    private GroupType intToType(int type) {
        switch (type) {
            case 0:
                return GroupType.GROUP_TYPE_LIST;
            case 1:
                return GroupType.GROUP_TYPE_MAP_2D;
            case 2:
                return GroupType.GROUP_TYPE_MAP_3D;
        }
        return GroupType.GROUP_TYPE_LIST;
    }

    private DataOrg stringToDataOrg(String dataOrg) {
        switch (dataOrg) {
            case "eByte":
                return DataOrg.eByte;
            case "eLoHi":
                return DataOrg.eLoHi;
            case "eHiLo":
                return DataOrg.eHiLo;
            case "eLoHiLoHi":
                return DataOrg.eLoHiLoHi;
            case "eHiLoHilo":
                return DataOrg.eHiloHilo;
            case "eFloatLoHi":
                return DataOrg.eFloatLoHi;
            case "eFloatHiLo":
                return DataOrg.eFloatHiLo;
        }

        return DataOrg.eByte;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public Address getAddress() {
        return address;
    }

    public DataOrg getDataOrg() {
        return dataOrg;
    }

    public GroupType getGroupType() {
        return type;
    }

    public Map<String,Integer> getSizes() {
        var sizes = new HashMap<String, Integer>();
        sizes.put("x", x);
        sizes.put("y", y);

        return sizes;
    }

    public void setSizes(int x, int y) {
        this.x = x;
        this.y = y;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public void setDataOrg(DataOrg dataOrg) {
        this.dataOrg = dataOrg;
    }

    public void setDataOrg(String dataOrg) {
        this.dataOrg = stringToDataOrg(dataOrg);
    }

    public void setGroupType(GroupType type) {
        this.type = type;
    }

    public void setGroupType(int type) {
        this.type = intToType(type);
    }

    public int getDataTypeSize()
    {
        switch (this.dataOrg) {
            case eByte:
                return 1;
            case eHiLo:
            case eLoHi:
                return 2;
            case eLoHiLoHi:
            case eHiloHilo:
                return 4;
            case eFloatHiLo:
            case eFloatLoHi:
                return 8;
        }

        return 1;
    }

    public static Group unserialize(String[] data) {
        return new Group(
                data[0],
                data[1],
                null,
                data[3],
                Integer.parseInt(data[2]),
                Integer.parseInt(data[5])
        );
    }
}
