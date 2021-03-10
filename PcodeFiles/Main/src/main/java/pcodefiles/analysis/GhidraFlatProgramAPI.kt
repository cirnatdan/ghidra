package pcodefiles.analysis

import ghidra.program.model.address.Address

interface GhidraFlatProgramAPI {
    fun toAddr(offset: Int): Address
    fun toAddr(offset: Long): Address
    fun findBytes(lastAddr: Address, s: String): Address?
    fun disassemble(address: Address): Boolean
}
