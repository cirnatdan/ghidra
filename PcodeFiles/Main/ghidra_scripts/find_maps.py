# Finds ECU maps locations
# @author dan@alt.md
# @category EDC17
# @keybinding
# @menupath
# @toolbar
import sys, os

sys.path.append(os.path.dirname(os.path.realpath(getSourceFile().getAbsolutePath())))

import json
import __main__ as ghidra_app
import utils
from ghidra.program.model.data import Pointer32DataType

from group import Group


def findPattern(pattern):
    matches = findBytes(toAddr(0x80004000), pattern, 2)
    if len(matches) == 0:
        return None
    if len(matches) <= 2:
        return matches[0]
    elif len(matches) > 2:
        raise Exception('not an exact match, found {}'.format(len(matches)))


def findPatternFuzzy(pattern):
    pattern = pattern[:8]
    return findPattern(pattern)


def run():
    start_of_data = utils.find_data_sector()
    if start_of_data is None:
        print("Could not find data sector")
        return
    print("Data sector starts at {}".format(start_of_data))
    software_version = utils.get_softwarever(utils.get_scriptcode_addr(start_of_data))
    scriptcode = utils.convert_scriptcode(software_version)
    print("Scriptcode: {}".format(scriptcode))
    listing = currentProgram.getListing()
    for_export = {
        "scriptcode": scriptcode,
        "softwareVersion": software_version,
        "maps": []
    }
    with open(os.path.join(getScriptArgs()[0],"code.patterns")) as file:
        for line in file:
            line = line.strip().split("::")
            group = Group(line[0])
            group.setName(line[1])
            group.setGroupType(line[2])
            group.setDataOrg(line[3])
            patterns = line[3:]

            for pattern in patterns:
                code_location = findPattern(pattern)
                if code_location is not None:
                    break
                if code_location is None:
                    print("Trying more tolerant search for {}".format(group.getId()))
                    code_location = findPatternFuzzy(pattern)

            if code_location is None:
                print("{} code could not be found with pattern {}".format(group.getId(), pattern))
                continue
            print("{} code found at {}".format(group.getId(), code_location))
            ghidra_app.disassemble(code_location)

            instruction = listing.getInstructionAt(code_location)

            input = instruction.getInputObjects()
            if type(input[1]).__name__ != "Register":
                input.reverse()

            if input[1].getName() == 'a9':
                offset = input[0]
                print("Found offset {} at 0x{}".format(offset, instruction.getAddress()))
            else:
                print("Could not find offset for {}".format(group.getId()))
                continue

            # compute size
            data_ptr = start_of_data.add(offset.getValue())
            data_addr = getDataAt(data_ptr)
            if data_addr is None:
                data_addr = createData(data_ptr, Pointer32DataType())
            next_data_ptr_addr = start_of_data.add(offset.getValue() + 4)
            next_data_ptr = getDataAt(next_data_ptr_addr)
            if next_data_ptr is None:
                next_data_ptr = createData(next_data_ptr_addr, Pointer32DataType())
            if group.getId() in ["KF00", "KF06", "KF07"]:
                size = next_data_ptr.getValue().subtract(data_addr.getValue()) / group.getDataTypeSize()
            print("Found {} at {} with size {}".format(group.getName(), data_addr, size))

            for_export["maps"].append({
                "name": group.getName(),
                "key": group.getId(),
                "sizes": {
                    "x": 1,
                    "y": size,
                },
                "address": utils.clean_hex(data_addr.getValue().getOffset() - 0x80000000)
            })

    print(json.JSONEncoder().encode(for_export))
    output_dir = getScriptArgs()[0]
    with open(os.path.join(output_dir, scriptcode + ".json"), 'w') as jsonFile:
        json.dump(for_export, jsonFile)


if __name__ == '__main__':
    run()
