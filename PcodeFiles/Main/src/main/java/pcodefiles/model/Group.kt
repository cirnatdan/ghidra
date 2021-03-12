package pcodefiles.model

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddress
import pcodefiles.model.Group.DataOrg
import pcodefiles.model.GroupType
import java.util.HashMap

class Group {
    var id: String
        protected set
    var name: String? = null
    var address: Address? = null

    enum class DataOrg {
        eByte, eLoHi, eHiLo, eLoHiLoHi, eHiloHilo, eFloatLoHi, eFloatHiLo
    }

    var dataOrg: DataOrg? = null
    var groupType: GroupType? = null
    var x = 0
    var y = 0
    var folderName: String? = null

    constructor(id: String) {
        this.id = id
    }

    constructor(id: String, name: String?, address: Address?, dataOrg: String, type: Int, length: Int) {
        this.id = id
        this.name = name
        this.address = address
        y = length
        groupType = intToType(type)
        this.dataOrg = stringToDataOrg(dataOrg)
    }

    private fun intToType(type: Int): GroupType {
        when (type) {
            0 -> return GroupType.GROUP_TYPE_LIST
            1 -> return GroupType.GROUP_TYPE_MAP_2D
            2 -> return GroupType.GROUP_TYPE_MAP_3D
        }
        return GroupType.GROUP_TYPE_LIST
    }

    private fun stringToDataOrg(dataOrg: String): DataOrg {
        when (dataOrg) {
            "eByte" -> return DataOrg.eByte
            "eLoHi" -> return DataOrg.eLoHi
            "eHiLo" -> return DataOrg.eHiLo
            "eLoHiLoHi" -> return DataOrg.eLoHiLoHi
            "eHiLoHilo" -> return DataOrg.eHiloHilo
            "eFloatLoHi" -> return DataOrg.eFloatLoHi
            "eFloatHiLo" -> return DataOrg.eFloatHiLo
        }
        return DataOrg.eByte
    }

    val sizes: Map<String, Int>
        get() {
            val sizes = HashMap<String, Int>()
            sizes["x"] = x
            sizes["y"] = y
            return sizes
        }

    fun setSizes(x: Int, y: Int) {
        this.x = x
        this.y = y
    }

    fun setDataOrg(dataOrg: String) {
        this.dataOrg = stringToDataOrg(dataOrg)
    }

    fun setGroupType(type: Int) {
        groupType = intToType(type)
    }

    val dataTypeSize: Int
        get() {
            when (dataOrg) {
                DataOrg.eByte -> return 1
                DataOrg.eHiLo, DataOrg.eLoHi -> return 2
                DataOrg.eLoHiLoHi, DataOrg.eHiloHilo -> return 4
                DataOrg.eFloatHiLo, DataOrg.eFloatLoHi -> return 8
            }
            return 1
        }

    fun dump(): Map<String, Any?> {
        return mapOf<String, Any?>(
            "id" to id,
            "name" to name,
            "dataOrg" to dataOrg.toString(),
            "address" to address!!.offset.toString(),
            "folderName" to folderName,
            "groupType" to groupType!!.ordinal
        )
    }

    companion object {
        @JvmStatic
        fun unserialize(data: Array<String>): Group {
            return Group(
                data[0],
                data[1],
                null,
                data[3], data[2].toInt(), data[5].toInt()
            )
        }

        @JvmStatic
        fun fromMap(map: Map<String, Any?>): Group {
            return Group(
                map["id"] as String,
                map["name"] as String,
                AddressSpace.EXTERNAL_SPACE.getAddress((map["address"] as String).toLong()),
                map["dataOrg"] as String,
                (map["groupType"] as Double).toInt(),
                0
            )
        }
    }
}