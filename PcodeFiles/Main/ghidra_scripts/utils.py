import sys

import __main__ as ghidra_app
this = sys.modules[__name__]
import ghidra

from ghidra.program.model.data import Pointer32DataType

data_sector_patterns = {
	"BMW": "(\x40|\x44)(\x1e\x30\x80)"
}

code_patterns = {
	"scriptcode": "\x99" + ".{3}"
				+ "\x8f" + ".{3}"
				+ "\x91" + ".{3}"
				+ "\x09" + ".{3}"
				+ "\xd9" + ".{3}",
	"end_of_code": "\x00\x90"
				+ "\x00\x00"
				+ "\x6d" + ".{3}"
				+ "\x6d\xff" + ".{2}"
				+ "\x1d\xff" + ".{2}",
}

def find_end_of_code():
	last_addr = ghidra_app.toAddr(0x80004000)
	found = None
	while True:
		last_addr = ghidra_app.findBytes(last_addr, code_patterns["end_of_code"])
		if last_addr is None:
			break
		else:
			found = last_addr
			last_addr = last_addr.add(16)
	ghidra_app.disassemble(found)

	return found

def find_data_sector():
	end_of_code = find_end_of_code()
	if end_of_code is not None:
		start_of_data = ghidra_app.findBytes(end_of_code, ".{2}\x30\x80.{2}\x30\x80")
	if start_of_data is not None:
		return start_of_data
	return ghidra_app.findBytes(ghidra_app.toAddr(0x80004000), this.data_sector_patterns["BMW"])


def extract_a9_offset(instruction):
	objects = instruction.getOpObjects(1)
	if type(objects[0]) == ghidra.program.model.lang.Register:
		return objects[1]
	elif type(objects[1]) == ghidra.program.model.lang.Register:
		return objects[0]

def get_scriptcode_addr(data_sector_addr):
	script_code_func_addr = ghidra_app.findBytes(ghidra_app.toAddr(0x80004000), this.code_patterns["scriptcode"])
	if script_code_func_addr is not None:
		print("Script code function at: {}".format(script_code_func_addr))
		ghidra_app.disassemble(script_code_func_addr)
		instruction = ghidra_app.getInstructionAt(script_code_func_addr)
		print("Script code instruction {} ".format(instruction))

		scriptcode_offset = extract_a9_offset(instruction)
		print("Script code offset: {}".format(scriptcode_offset))

		scriptcode_ptr_addr = data_sector_addr.add(scriptcode_offset.getValue())
		print("Script code pointer at: {}".format(scriptcode_ptr_addr))

		ghidra_app.removeDataAt(scriptcode_ptr_addr)
		scriptcode_addr = ghidra_app.createData(scriptcode_ptr_addr, Pointer32DataType())
		print("Script code addr: {}".format(scriptcode_addr))	

		return scriptcode_addr.getValue()
	else:
		addr = data_sector_addr
		while True:
			ptr = ghidra_app.getDataAt(addr)			
			if type(ptr).__name__ != "Pointer32DataType":
				ghidra_app.removeDataAt(addr)
			if ptr is None:
				ptr = ghidra_app.createData(addr, Pointer32DataType())

			if ptr.getValue().getOffset() > 0x90000000:
				return

			bytez = [b & 0xff for b in ghidra_app.getBytes(ptr.getValue(), 8)]

			if bytez[0:3] == [0x4f, 0x5f, 0x37]:				
				return ptr.getValue()
			addr = addr.add(4)

def get_softwarever(softwarever_addr):
	if ghidra_app.getDataAt(softwarever_addr):
		ghidra_app.removeDataAt(softwarever_addr)
	softwarever = ghidra_app.createAsciiString(softwarever_addr).getValue()
	return softwarever

def convert_scriptcode(scriptcode_raw):
	return "V" + scriptcode_raw[3:7]

def clean_hex(d):
	'''
     Convert decimal to hex and remove the "L" suffix that is appended to large
     numbers
     '''
	return hex(d).rstrip('L')