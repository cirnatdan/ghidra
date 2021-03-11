package pcodefiles.analysis

import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer32DataType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Instruction
import ghidra.program.model.scalar.Scalar
import kotlin.experimental.and

interface Utils: GhidraFlatProgramAPI {
    val codePatterns
        get() = mapOf(
            "end_of_code" to "\\x00\\x90"
                    + "\\x00\\x00"
                    + "\\x6d" + ".{3}"
                    + "\\x6d\\xff" + ".{2}"
                    + "\\x1d\\xff" + ".{2}",
            "scriptcode" to "\\x99" + ".{3}"
                    + "\\xa6" + ".{1}"
                    + "\\x37" + ".{3}"
                    + "\\x09" + ".{3}"
                    + "\\x3f" + ".{3}",
        )

    val data_sector_patterns
        get() = mapOf(
            "BMW" to "(\\x40|\\x44)(\\x1e\\x30\\x80)"
        )

    fun findEndOfCode(): Address? {
        var lastAddress: Address? = toAddr(0x80004000)
        var found: Address? = null
        while(true) {
            lastAddress = findBytes(lastAddress!!, codePatterns["end_of_code"]!!)
            if (lastAddress == null) {
                break
            } else {
                found = lastAddress
                lastAddress = lastAddress.add(16)
            }
        }
        if (found == null)
            return null
        disassemble(found)
        return found
    }

    fun findDataSector(): Address? {
        val endOfCode = findEndOfCode() ?: return null
        var startOfData = findBytes(endOfCode, ".{2}\\x30\\xa0.{2}\\x30\\xa0")
        if (startOfData != null )
            return startOfData

        startOfData = findBytes(endOfCode, ".{2}\\x30\\x80.{2}\\x30\\x80")
        return findBytes(toAddr(0x80004000), data_sector_patterns["BMW"]!!)
    }

    fun extract_a9_offset(instruction: Instruction): Scalar {
        val objects = instruction.getOpObjects(1)
        if (objects[0] is Register)
            return objects[1] as Scalar
        else if(objects[1] is Register)
            return objects[0] as Scalar
        throw Exception("Offset could not be extracted")
    }

    fun get_scriptcode_addr(data_sector_addr: Address): Address? {
        val script_code_func_addr = findBytes(toAddr(0x80004000), codePatterns["scriptcode"]!!)
        if (script_code_func_addr != null) {
            println("Script code function at: $script_code_func_addr")
            disassemble(script_code_func_addr)
            val instruction = getInstructionAt(script_code_func_addr)
            print("Script code instruction $instruction")

            val scriptcode_offset: Scalar = extract_a9_offset(instruction)
            print("Script code offset: {}".format(scriptcode_offset))

            val scriptcode_ptr_addr = data_sector_addr.add(scriptcode_offset.getValue())
            print("Script code pointer at: {}".format(scriptcode_ptr_addr))

            removeDataAt(scriptcode_ptr_addr)
            val scriptcode_addr = createData(scriptcode_ptr_addr, Pointer32DataType())
            print("Script code addr: {}".format(scriptcode_addr))

            return scriptcode_addr.value as Address
        } else {
            var addr = data_sector_addr
            while (true) {
                var ptr = getDataAt(addr)
                if (ptr !is Pointer32DataType) {
                    removeDataAt(addr)
                }
                if (ptr == null)
                    ptr = createData(addr, Pointer32DataType())

                if (ptr.value is Address && (ptr.value as Address).offset > 0x90000000)
                    return null

                val bytez = getBytes(ptr.value as Address, 8).map {
                    it.and(0xff.toByte())
                }

                if (bytez.subList(0, 3).equals(listOf(0x4f, 0x5f, 0x37))){
                    return ptr.value as Address?
                }

                addr = addr.add(4)
            }
        }
    }

    fun get_softwarever(softwareverAddr: Address): String {
        if (getDataAt(softwareverAddr) != null)
            removeDataAt(softwareverAddr)
        return createAsciiString(softwareverAddr).value as String
    }

    fun convert_scriptcode(scriptcode_raw: String): String {
        val parts = scriptcode_raw.split("-")
        return "V" + parts[0].substring(3)
    }

    fun compute_map_size(data_sector_addr: Address, offset: Long, data_type_size: Int): Long {
        val dataPtr = data_sector_addr.add(offset)
        var dataAddr = getDataAt(dataPtr)
        if (dataAddr == null)
            dataAddr = createData(dataPtr, Pointer32DataType())
        var nextDataPtrAddr = data_sector_addr.add(offset + 4)
        var nextDataPtr = getDataAt(nextDataPtrAddr)
        if (nextDataPtr == null)
            nextDataPtr = createData(nextDataPtrAddr, Pointer32DataType())
        return (nextDataPtr.value as Address).subtract(dataAddr.value as Address) / data_type_size
    }
}