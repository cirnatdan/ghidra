import sys,os,struct
sys.path.append(os.path.dirname(os.path.realpath(getSourceFile().getAbsolutePath())))
import __main__ as ghidra_app
from ghidra.program.model.data import Pointer32DataType
import utils
this = sys.modules[__name__]

def run():
	print("Looking up characteristics in data sector table")
	data_sector_addr = utils.find_data_sector()
	pointer_addr = data_sector_addr

	while True:
		data = getBytes(pointer_addr, 4)
		data = struct.unpack("BBBB", data[0:4])

		value = 0x1 * data[0]
		value += 0x100 * data[1]
		value += 0x10000 * data[2]
		value += 0x1000000 * data[3]

		if ((value > 0x81000000 and value < 0xa0000000) or value > 0xa1000000):
			break
		pointer = createData(pointer_addr, Pointer32DataType())
		createLabel(pointer.getValue(), "DAT_{}".format(utils.clean_hex(value)), True)
		pointer_addr = pointer_addr.add(4) #next

if __name__ == '__main__':
	run()