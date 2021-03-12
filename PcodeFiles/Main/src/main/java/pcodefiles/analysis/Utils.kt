package pcodefiles.analysis

import ghidra.app.plugin.core.searchmem.HexSearchFormat
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer32DataType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.CodeUnitIterator
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.InstructionIterator
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

    val dataSectorPatterns
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
        val startOfData = findBytes(endOfCode, ".{2}\\x30\\xa0.{2}\\x30\\xa0")
        if (startOfData != null )
            return startOfData

        return findBytes(toAddr(0x80004000), dataSectorPatterns["BMW"]!!)
            ?: findBytes(endOfCode, ".{2}\\x30\\x80.{2}\\x30\\x80")
    }

    fun extractA9Offset(instruction: Instruction): Scalar {
        val objects = instruction.getOpObjects(1)
        if (objects[0] is Register)
            return objects[1] as Scalar
        else if(objects[1] is Register)
            return objects[0] as Scalar
        throw Exception("Offset could not be extracted")
    }

    fun getScriptcodeAddress(dataSectorAddress: Address): Address? {
        val scriptCodeFuncAddress = findBytes(toAddr(0x80004000), codePatterns["scriptcode"]!!)
        if (scriptCodeFuncAddress != null) {
            println("Script code function at: $scriptCodeFuncAddress")
            disassemble(scriptCodeFuncAddress)
            val instruction = getInstructionAt(scriptCodeFuncAddress)
            println("Script code instruction $instruction")

            val scriptcodeOffset: Scalar = extractA9Offset(instruction)
            println("Script code offset: $scriptcodeOffset")

            val scriptcodePtrAddress = dataSectorAddress.add(scriptcodeOffset.value)
            println("Script code pointer at: $scriptcodePtrAddress")

            removeDataAt(scriptcodePtrAddress)
            val scriptcodeAddress = createData(scriptcodePtrAddress, Pointer32DataType())
            println("Script code address: $scriptcodeAddress")

            return scriptcodeAddress.value as Address
        } else {
            var address = dataSectorAddress
            while (true) {
                var ptr = getDataAt(address)
                if (ptr !is Pointer32DataType) {
                    removeDataAt(address)
                }
                if (ptr == null)
                    ptr = createData(address, Pointer32DataType())

                if (ptr.value is Address && (ptr.value as Address).offset > 0x90000000)
                    return null

                val bytez = getBytes(ptr.value as Address, 8).map {
                    it.and(0xff.toByte())
                }

                if (bytez.subList(0, 3) == listOf(0x4f, 0x5f, 0x37)){
                    return ptr.value as Address?
                }

                address = address.add(4)
            }
        }
    }

    fun getSoftwareVersion(softwareVersionAddress: Address): String {
        if (getDataAt(softwareVersionAddress) != null)
            removeDataAt(softwareVersionAddress)
        return createAsciiString(softwareVersionAddress).value as String
    }

    fun convertScriptcode(scriptcode_raw: String): String {
        val parts = scriptcode_raw.split("-")
        return "V" + parts[0].substring(3)
    }

    fun computeMapSize(dataSectorAddress: Address, offset: Long, data_type_size: Int): Long {
        val dataPtr = dataSectorAddress.add(offset)
        var dataAddress = getDataAt(dataPtr)
        if (dataAddress == null)
            dataAddress = createData(dataPtr, Pointer32DataType())
        val nextDataPtrAddress = dataSectorAddress.add(offset + 4)
        var nextDataPtr = getDataAt(nextDataPtrAddress)
        if (nextDataPtr == null)
            nextDataPtr = createData(nextDataPtrAddress, Pointer32DataType())
        return (nextDataPtr.value as Address).subtract(dataAddress.value as Address) / data_type_size
    }

    fun getInstructionsPattern(code_units: CodeUnitIterator): String {
        var pattern = ""
        var count = 0
        for (cu in code_units) {
            count += 1
            if (count > 5)
                return pattern
            val bytes = cu.bytes
            pattern += "\\x%02x.{%d}".format(cu.getUnsignedByte(0), bytes.size - 1)
        }
        return ""
    }

    fun findOffsetInCode(instructions: InstructionIterator, offset: Long): Address? {
        for (i in instructions) {
            val input = i.inputObjects
            if (input.size != 2)
                continue
            if (input[1] !is Register)
                input.reverse()
            if (input[1] is Register
                && (input[1] as Register).name == "a9"
                && (input[0] as Scalar).value == offset) {
                println("Found offset %x at 0x%x: %s".format(offset, i.address.offset, i))
                return i.address
            }
        }
        return null
    }

    fun hexStringToLittleEndianPattern(input: String): String {
        val searchFormat = HexSearchFormat {}
        val searchData = searchFormat.getSearchData(input)
        return searchData.bytes.joinToString(separator = "", transform = {
            "\\x%02x".format(it)
        })
    }

    fun getMapOffset(dataSectorAddress: Address, mapAddress: Address): Long {
        val mapAddressSearch = hexStringToLittleEndianPattern(mapAddress.toString())
        val ptrAddress = findBytes(dataSectorAddress, mapAddressSearch)
        if (ptrAddress == null) {
            throw Exception("Can't find map pointer for %s".format(mapAddress))
        }
        return ptrAddress.subtract(dataSectorAddress)
    }

    fun hasSuboffsetInCode(instructions: InstructionIterator, suboffset: Long): Boolean {
        val result = instructions.next().resultObjects
        // print(result)
        val suboffsetRegister = (result[0] as Register).name
        // print(suboffset_register)

        var i = 0
        while (true) {
            if (i > 5)
                return false
            val instr = instructions.next()
            val input = instr.inputObjects
            if (input.size != 2)
                continue
            if (input[1] !is Register)
                input.reverse()
            if (input[1] is Register
                && (input[1] as Register).name == suboffsetRegister
                && (input[0] as Scalar).value == suboffset) {
                print("Found suboffset 0x%x at 0x%x: %s".format(suboffset, instr.address, instr))
                return true
            }
            i += 1
        }
    }
}