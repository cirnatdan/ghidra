import sys, os, json

sys.path.append(os.path.dirname(os.path.realpath(getSourceFile().getAbsolutePath())))

from winols_parser import Lark_StandAlone, Token, Tree
from Queue import Queue

import __main__ as ghidra_app
from ghidra.framework.options import SaveState
from pcodefiles.model import Group, GroupType
from pcodefiles.analysis import UtilsHelper
from group import GroupContainer

utils_helper = UtilsHelper(getCurrentProgram(), monitor)

this = sys.modules[__name__]

groups = Queue()
groups_export = []
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
    group.setAddress(toAddr(int(address.value, 16) + 0x80000000))

    if group_id.value in this.groups_types:
        this.groups_types[group_id.value] += 1
        group.setGroupType(group.getGroupType() + 1)
    else:
        this.groups_types[group_id.value] = 0
        group.setGroupType(0)


def setMapProperty(groupId, command):
    group = this.group_container.get(groupId)
    _, prop, value = command.children
    prop = prop.value[1:-1]  # remove quotes
    value = value.value[1:-1]

    if prop == "DataOrg":
        this.groups.put([groupId, value])
        this.groups_export.append(dict(group.dump()))
        group.setDataOrg(value)
    elif prop == "Name":
        group.setName(value)
    elif prop == "FolderName":
        group.setFolderName(value)

def openWinOLSScript():
    return open(getScriptArgs()[0])


def main():
    parser = Lark_StandAlone()

    with openWinOLSScript() as f:
        parse_tree = parser.parse(f.read())
        for global_command in parse_tree.children:
            walkTree(global_command)

    project = state.getProject()
    parsed_state = SaveState()
    parsed_state.putString("winOLS_groups", json.JSONEncoder().encode(this.groups_export))
    project.setSaveableData("winOLSParseResult", parsed_state)


if __name__ == "__main__":
    print("version_with_helper")
    main()
