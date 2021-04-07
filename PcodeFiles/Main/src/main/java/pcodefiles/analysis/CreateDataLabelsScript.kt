package pcodefiles.analysis

import ghidra.app.script.GhidraScript
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer32DataType

class CreateDataLabelsScript(): GhidraScript(), Utils {
    override fun run() {
        println("Looking up characteristics in data sector table")
        val data_sector_addr = find_data_sector()
        var pointer_addr = data_sector_addr

        while (true) {
            var pointer = createData(pointer_addr, Pointer32DataType())
            var value = pointer.value
            if (value !is Address) {
                break
            }

            if ((value.offset in 0x81000001..0x9fffffff) || value.offset > 0xa1000000)
                break
            createLabel(value, "DAT_{}".format(value.toString()), true)
            pointer_addr = pointer_addr.add(4) //next
        }
    }
}