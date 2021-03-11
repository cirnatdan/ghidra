package pcodefiles.analysis

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Instruction

interface GhidraFlatProgramAPI {
    fun toAddr(offset: Int): Address
    fun toAddr(offset: Long): Address
    fun findBytes(address: Address, s: String): Address?
    fun disassemble(address: Address): Boolean
    fun getInstructionAt(address: Address): Instruction
    fun removeDataAt(address: Address)
    fun createData(address: Address, dataType: DataType): Data
    fun getDataAt(address: Address): Data?
    fun getBytes(address: Address, length: Int): ByteArray
    fun createAsciiString(address: Address): Data
}
