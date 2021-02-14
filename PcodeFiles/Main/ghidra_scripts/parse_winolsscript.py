import sys, os

sys.path.append(os.path.dirname(os.path.realpath(getSourceFile().getAbsolutePath())))

from winols_parser import Lark_StandAlone, Token, Tree
from Queue import Queue

import __main__ as ghidra_app
import utils
from group import Group, GroupContainer

this = sys.modules[__name__]

groups = Queue()
group_container = GroupContainer()

groups_address = {}
groups_types = {}

def walkTree(command):
	if command.data == "block_executable":
		for command in command.children:
			walkExecutable(command)

def walkExecutable(command):
	if isinstance(command, Token):
		print(command)
	if isinstance(command, Tree):
		if command.data == "search":
			walkSearch(command)
		if command.data == "insert_map_block":
			walkInsertMap(command)

def walkInsertMap(command):
	groupName = None
	for command in command.children:
		if isinstance(command, Token) and command.type == "GROUP_NAME":
			groupName = command.value
			continue
		if isinstance(command, Tree) and command.data == "set_map_property":
			setMapProperty(groupName, command)

def walkSearch(command):
	search, group_id, data_organisation, address, deviation, tolerance, pattern = command.children
	group = this.group_container.get(group_id.value)
	group.setAddress(int(address.value, 16))

	if group_id.value in this.groups_types:
		this.groups_types[group_id.value] += 1
		group.setGroupType(group.getGroupType() + 1)
	else:
		this.groups_types[group_id.value] = 0
		group.setGroupType(0)

def setMapProperty(groupId, command):
	group = this.group_container.get(groupId)
	_, prop, value = command.children
	prop = prop.value[1:-1] #remove quotes
	value = value.value[1:-1]

	if prop == "DataOrg":
		this.groups.put([groupId, value])
		group.setDataOrg(value)
	elif prop == "Name":
		group.setName(value)
	elif prop == "FolderName":
		group.setFolderName(value)

def matchMap(group):
	if group.getGroupType() == Group.GROUP_TYPE_LIST:
		address = group.getAddress()
	else:
		address = group.getAddress() + group.getDataTypeSize()

	address = 0x80000000 + address
	
	symbol = getSymbolAt(toAddr(address))
	if symbol is None:
		near_symbol = getSymbolBefore(toAddr(address))
		this.not_found_maps.append([group, address, near_symbol])
	else:
		this.found_maps.append([group, address])

def get_map_offset(data_sector_addr, map_addr):
	map_addr_search = hex_string_to_little_endian_pattern(map_addr.toString())
	ptr_addr = findBytes(data_sector_addr, map_addr_search)
	if ptr_addr is None:
		raise Exception("Can't find map pointer for {}".format(map_addr))
	return ptr_addr.subtract(data_sector_addr)

def hex_string_to_little_endian_pattern(string):
	byte_list = []
	for i in range(0, len(string), 2):
		byte_list.append(string[i:i+2])
	byte_list.append("")
	return "\\x".join(reversed(byte_list))

def find_offset_in_code(instructions, offset):
	for i in instructions:
		input = i.getInputObjects()
		if len(input) != 2:
			continue
		if type(input[1]).__name__ != "Register":
			input.reverse()
		if type(input[1]).__name__ == "Register" and input[1].getName() == 'a9' and input[0].getValue() == offset:
			print("Found offset {} at 0x{}: {}".format(hex(offset), i.getAddress(), i))
			return i.getAddress()

def has_suboffset_in_code(instructions, suboffset):
	result = instructions.next().getResultObjects()
	#print(result)
	suboffset_register = result[0].getName()
	#print(suboffset_register)

	i = 0
	while True:
		if i > 5:
			return False
		instr = instructions.next()
		input = instr.getInputObjects()
		if len(input) != 2:
			continue
		if type(input[1]).__name__ != "Register":
			input.reverse()
		if type(input[1]).__name__ == "Register" and input[1].getName() == suboffset_register and input[0].getValue() == suboffset:
			print("Found suboffset {} at 0x{}: {}".format(hex(suboffset), instr.getAddress(), instr))
			return True
		i += 1

def get_instructions_pattern(code_units):
	pattern = ""
	count = 0
	for cu in code_units:
		count += 1
		if count > 5:
			return pattern
		bytez = cu.getBytes()
		pattern += "\\x{:02x}.{{{}}}".format(cu.getUnsignedByte(0), len(bytez) - 1)

def openWinOLSScript():
	return open(getScriptArgs()[0])

def main():
	parser = Lark_StandAlone()

	with openWinOLSScript() as f:
		parse_tree = parser.parse(f.read())
		for global_command in parse_tree.children:
			walkTree(global_command)

	this.found_maps = []
	this.not_found_maps = []
	while not this.groups.empty():
		entry = this.groups.get()
		group = this.group_container.get(entry[0])
		matchMap(group)

	print("Found:")
	for i in this.found_maps:
		print("{} {}".format(i[0].getId(), hex(i[1])))
	print("Not Found:")
	for i in this.not_found_maps:
		print("{} {}, closest: {} {}".format(i[0].getId(), hex(i[1]), i[2], i[2].getAddress() if i[2] else None))

	data_sector_addr = utils.find_data_sector()
	print("Data sector starts at: {}".format(data_sector_addr))

	listing = getCurrentProgram().getListing()
	f = open(os.path.join(getScriptArgs()[1],"code.patterns"), "w+")
	for m in this.found_maps:
		group = m[0]
		map_offset = get_map_offset(data_sector_addr, toAddr(m[1]))
		print("{} offset: {}".format(group.getId(), hex(map_offset)))
		line = [
			group.getId(),
			group.getName(),
			str(group.getGroupType()),
			group.getDataOrg(),
			str(map_offset),
			group.getFolderName(),
			str(-1), # no suboffset
		]
		code_addr = find_offset_in_code(listing.getInstructions(toAddr(0x80004000), True), map_offset)
		while code_addr is not None:
			line.append(get_instructions_pattern(listing.getCodeUnits(code_addr, True)))
			code_addr = find_offset_in_code(listing.getInstructions(code_addr.add(16), True), map_offset)
		f.write("::".join(line) + '\n')

	for m in this.not_found_maps:
		group = m[0]
		map_offset = get_map_offset(data_sector_addr, m[2].getAddress())
		print("{} offset: {}".format(group.getId(), hex(map_offset)))
		map_suboffset = m[1] - m[2].getAddress().getOffset()
		print("{} suboffset: {}".format(group.getId(), hex(map_suboffset)))
		line = [
			group.getId(),
			group.getName(),
			str(group.getGroupType()),
			group.getDataOrg(),
			str(map_offset),
			group.getFolderName(),
			str(map_suboffset),
		]
		code_addr = find_offset_in_code(listing.getInstructions(toAddr(0x80004000), True), map_offset)
		while code_addr is not None:
			found_suboffset = has_suboffset_in_code(listing.getInstructions(code_addr, True), map_suboffset)
			if found_suboffset is True:
				line.append(get_instructions_pattern(listing.getCodeUnits(code_addr, True)))
				break
			code_addr = find_offset_in_code(listing.getInstructions(code_addr.add(16), True), map_offset)

		f.write("::".join(line) + '\n')

	f.truncate()
	f.close()

if __name__ == "__main__":
	print("version2")
	main()
