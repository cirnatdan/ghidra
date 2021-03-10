package pcodefiles.analysis

import ghidra.app.script.GhidraScript
import ghidra.program.model.listing.Program

class PossibleOffsetsAnalyzerScript(
) : GhidraScript(), Utils {

    val a9_access_patterns
        get() = arrayOf(
            "\\x99\\x91",
            "\\x99\\x92",
            "\\x99\\x93",
            "\\x99\\x94",
            "\\x99\\x95",
            "\\x99\\x96",
            "\\x99\\x97",
            "\\x99\\x98",
            "\\x99\\x99",
            "\\x99\\x9a",
            "\\x99\\x9b",
            "\\x99\\x9c",
            "\\x99\\x9d",
            "\\x99\\x9e",
            "\\x99\\x9f",
            "\\x19\\x91",
            "\\x19\\x92",
            "\\x19\\x93",
            "\\x19\\x94",
            "\\x19\\x95",
            "\\x19\\x96",
            "\\x19\\x97",
            "\\x19\\x98",
            "\\x19\\x99",
            "\\x19\\x9a",
            "\\x19\\x9b",
            "\\x19\\x9c",
            "\\x19\\x9d",
            "\\x19\\x9e",
            "\\x19\\x9f",
        )

    override fun run() {
        print("Looking for possible offsets instructions in $currentProgram")
        val data_sector_addr = find_data_sector()

        for (p in a9_access_patterns) {
            var addr = findBytes(toAddr(0x80004000), p)
            while (addr != null) {
                if (addr > data_sector_addr)
                    break
                disassemble(addr)
                addr = findBytes(addr.add(1), p)
            }
        }
    }

}