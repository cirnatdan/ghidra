package pcodefiles.analysis

import ghidra.app.script.GhidraScript
import ghidra.framework.options.SaveState

class FindMapsScript(
    val report: SaveState
): GhidraScript(), Utils {
    override fun run() {
        val startOfData = findDataSector()
        if (startOfData == null) {
            println("Could not find data sector!")
            val badFiles = report.getStrings("badFiles", arrayOf()).toMutableList()
            badFiles.add(currentProgram.name)
            report.putStrings("badFiles", badFiles.toTypedArray())
            return
        }

        println("Data sector starts at $startOfData")
        val software_version = get_softwarever(get_scriptcode_addr(startOfData)!!)
        val scriptcode = convert_scriptcode(software_version)
        println("Scriptcode: $scriptcode")
        val listing = currentProgram.listing
    }
}