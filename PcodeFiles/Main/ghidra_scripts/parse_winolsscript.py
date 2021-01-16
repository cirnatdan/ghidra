import sys, os

sys.path.append(os.path.dirname(os.path.realpath(getSourceFile().getAbsolutePath())))

from winols_parser import Lark_StandAlone, Token, Tree
from Queue import Queue

import __main__ as ghidra_app
import utils
from group import Group, GroupContainer

this = sys.modules[__name__]

GRAMMAR = r"""
start: (global_command | global_block)*

global_command: REQUIRES_WINOLS ESCAPED_STRING
	| REQUIRES_HEXDUMP
	| requires_map
	| replace_mode

requires_map: REQUIRES_MAP
	| REQUIRES_MAP "\[" INT INT "\]" 

replace_mode: REPLACE_MODE MODE_PARAMETER
	| REPLACE_MODE MODE_PARAMETER MODE_PARAMETER
	| REPLACE_MODE MODE_PARAMETER MODE_PARAMETER MODE_PARAMETER
	| REPLACE_MODE "all"

global_block: BEGIN_REQUIRES non_global_command+ END_REQUIRES -> block_requires
	| BEGIN_EXECUTABLE (non_global_command|insert_map_block)+ END_EXECUTABLE -> block_executable

insert_map_block: BEGIN_INSERT_MAP GROUP_NAME non_global_command+ END_INSERT_MAP

non_global_command: CHECK_PROPERTY ESCAPED_STRING ESCAPED_STRING -> check_property
	| SEARCH GROUP_NAME DATA_ORGANISATION ADDRESS DEVIATION TOLERANCE ESCAPED_STRING -> search
	| SET_MAP_PROPERTY ESCAPED_STRING ESCAPED_STRING -> set_map_property



REQUIRES_WINOLS: "requires_winols"
REQUIRES_HEXDUMP: "requires_hexdump"
REQUIRES_MAP: "requires_map"
REPLACE_MODE: "replace_mode"
BEGIN_REQUIRES: "begin_requires"
END_REQUIRES: "end_requires"
BEGIN_EXECUTABLE: "begin_executable"
END_EXECUTABLE: "end_executable"
BEGIN_INSERT_MAP: "begin_insert_map"
END_INSERT_MAP: "end_insert_map"
SEARCH: "search"
SEARCH_BY_MAPID: "search_by_mapid"
REPLACE: "replace"
UNIQUE: "unique"
SET_MAP_PROPERTY: "set_map_property"
CHECK_PROPERTY: "check_property"
MESSAGEBOX: "MessageBox"
MODE_PARAMETER: "percent"|"absolute"|"difference2"
DATA_ORGANISATION: "eLoHiLoHi"|"eHiLoHiLo"|"eByte"|"eLoHi"|"eHiLo"
DEVIATION: INT
TOLERANCE: INT "%"
GROUP_NAME: WORD INT
ADDRESS: "0x" HEXDIGIT+
COMMENT: "//" /[^\n]/*
%ignore COMMENT
%import common.WS
%ignore WS
%import common.ESCAPED_STRING
%import common.INT
%import common.NUMBER
%import common.WORD
%import common.HEXDIGIT
"""

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
	if isRunningHeadless():
		return open(getScriptArgs()[0])
	else:
		return open(getState().getProject().getSaveableData("WINOLS").getFile("winolsscript", None).getAbsolutePath())
		
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
		print("{} {}, closest: {} {}".format(i[0], hex(i[1]), i[2], i[2].getAddress() if i[2] else None))

	data_sector_addr = utils.find_data_sector()
	print("Data sector starts at: {}".format(data_sector_addr))

	listing = getCurrentProgram().getListing()
	f = open("code.patterns", "w+")
	for m in this.found_maps:
		group = m[0]
		map_offset = get_map_offset(data_sector_addr, toAddr(m[1]))
		print("{} offset: {}".format(group.getId(), hex(map_offset)))
		code_addr = find_offset_in_code(listing.getInstructions(toAddr(0x80004000), True), map_offset)
		line = [group.getId(), group.getName(), str(group.getGroupType()), group.getDataOrg()]
		while code_addr is not None:
			line.append(get_instructions_pattern(listing.getCodeUnits(code_addr, True)))
			code_addr = find_offset_in_code(listing.getInstructions(code_addr.add(16), True), map_offset)
		f.write("::".join(line) + '\n')

	f.truncate()
	f.close()

if __name__ == "__main__":
	print("version2")
	main()
