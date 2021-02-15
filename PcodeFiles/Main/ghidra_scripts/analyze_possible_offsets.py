import sys,os,struct
sys.path.append(os.path.dirname(os.path.realpath(getSourceFile().getAbsolutePath())))
import __main__ as ghidra_app
from ghidra.program.model.data import Pointer32DataType
import utils
this = sys.modules[__name__]

a9_access_patterns = [
	'\x99\x91',
	'\x99\x92',
	'\x99\x93',
	'\x99\x94',
	'\x99\x95',
	'\x99\x96',
	'\x99\x97',
	'\x99\x98',
	'\x99\x99',
	'\x99\x9a',
	'\x99\x9b',
	'\x99\x9c',
	'\x99\x9d',
	'\x99\x9e',
	'\x99\x9f',
	'\x19\x91',
	'\x19\x92',
	'\x19\x93',
	'\x19\x94',
	'\x19\x95',
	'\x19\x96',
	'\x19\x97',
	'\x19\x98',
	'\x19\x99',
	'\x19\x9a',
	'\x19\x9b',
	'\x19\x9c',
	'\x19\x9d',
	'\x19\x9e',
	'\x19\x9f',
]

def run():
	print("Looking for possible offsets instructions in " + currentProgram.toString())
	data_sector_addr = utils.find_data_sector()
	for p in a9_access_patterns:
		addr = findBytes(toAddr(0x80004000), p)
		while addr is not None:
			if addr > data_sector_addr:
				break
			#print("Disassembling binary at {} ".format(addr))
			disassemble(addr)
			addr = findBytes(addr.add(1), p)

if __name__ == '__main__':
	run()