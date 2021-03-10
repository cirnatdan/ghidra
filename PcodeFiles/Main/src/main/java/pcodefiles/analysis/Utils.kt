package pcodefiles.analysis

import ghidra.program.model.address.Address

interface Utils: GhidraFlatProgramAPI {
    val codePatterns
        get() = mapOf(
            "end_of_code" to "\\x00\\x90"
                    + "\\x00\\x00"
                    + "\\x6d" + ".{3}"
                    + "\\x6d\\xff" + ".{2}"
                    + "\\x1d\\xff" + ".{2}",
        )

    val data_sector_patterns
        get() = mapOf(
            "BMW" to "(\\x40|\\x44)(\\x1e\\x30\\x80)"
        )

    fun find_end_of_code(): Address? {
        var last_addr: Address? = toAddr(0x80004000)
        var found: Address? = null
        while(true) {
            last_addr = findBytes(last_addr!!, codePatterns["end_of_code"]!!)
            if (last_addr == null) {
                break
            } else {
                found = last_addr
                last_addr = last_addr.add(16)
            }
        }
        disassemble(found!!)
        return found
    }

    fun find_data_sector(): Address {
        val endOfCode = find_end_of_code()
        var startOfData: Address? = null
        if (endOfCode != null) {
            startOfData = findBytes(endOfCode, ".{2}\\x30\\xa0.{2}\\x30\\xa0")
        }
        if (startOfData != null )
            return startOfData

        startOfData = findBytes(endOfCode!!, ".{2}\\x30\\x80.{2}\\x30\\x80")
        return findBytes(toAddr(0x80004000), data_sector_patterns["BMW"]!!)!!
    }
}