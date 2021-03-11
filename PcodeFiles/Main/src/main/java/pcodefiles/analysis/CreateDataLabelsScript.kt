package pcodefiles.analysis

import ghidra.app.script.GhidraScript
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer32DataType

class CreateDataLabelsScript(): GhidraScript(), Utils {
    override fun run() {
        println("Looking up characteristics in data sector table")
        val dataSectorAddr = findDataSector()
        if (dataSectorAddr == null) {
            println("Could not find data sector")
            return
        }
        var pointerAddr = dataSectorAddr

        while (true) {
            val pointer = createData(pointerAddr!!, Pointer32DataType())
            val value = pointer.value
            if (value !is Address) {
                break
            }

            if ((value.offset in 0x81000001..0x9fffffff) || value.offset > 0xa1000000)
                break
            createLabel(value, "DAT_{}".format(value.toString()), true)
            pointerAddr = pointerAddr.add(4) //next
        }
    }
}