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

from pcodefiles.model import Group


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

def readSizeReuse(filepath):
    sizeReuse = {}
    with open(filepath) as file:
        for line in file:
            line = line.strip().split("::")
            return {
                'from': line[0],
                'to': line[1],
                'folder': line[2]
            }

    return sizeReuse

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
        "softwaresize": "{:x}".format(getProgramFile().length()),
        "maps": []
    }
    found_groups = {}
    with open(os.path.join(getScriptArgs()[0],"code.patterns")) as file:
        for line in file:
            line = line.strip().split("::")
            group = Group(line[0])
            group.setName(line[1])
            group.setGroupType(int(line[2]))
            group.setDataOrg(line[3])
            initial_offset = int(line[4])
            group.setFolderName(line[5])
            suboffset = int(line[6])
            patterns = line[7:]

            offsets = set()
            for pattern in patterns:
                code_location = findPattern(pattern)
                if code_location is not None:
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
                    offsets |= {offset.getValue()}
                    closest_offset = offset.getValue() # initial value
                else:
                    print("{} code could not be found with pattern {}".format(group.getId(), pattern))

            if len(offsets) == 0:
                print("No code or offsets found for group".format(group.getId()))
                continue

            probable_address = {}
            for offset in offsets:
                # compute size
                data_ptr = start_of_data.add(offset)
                data_addr = getDataAt(data_ptr)
                if data_addr is None:
                    data_addr = createData(data_ptr, Pointer32DataType())
                probable_address[offset] = data_addr.getValue()
                size = utils.compute_map_size(start_of_data, offset, group.getDataTypeSize())
                print("Found probable {} at {} with size {}".format(group.getName(), data_addr, size))
                print(offset, initial_offset, closest_offset)
                if abs(offset - initial_offset) < abs(closest_offset - initial_offset):
                    closest_offset = offset

            print("Closest offset is 0x{:x}".format(closest_offset))
            group.setSizes(1, size)
            group.setAddress(probable_address[closest_offset])
            if (suboffset > 0):
                group.setAddress(group.getAddress().add(suboffset))
            found_groups[group.getId()] = group

    sizeReuseRule = readSizeReuse(os.path.join(getScriptArgs()[0],"size.reuse"))
    if sizeReuseRule["from"] in found_groups and sizeReuseRule["to"] in found_groups:
        fromGroup = found_groups[sizeReuseRule["from"]]
        toGroup = found_groups[sizeReuseRule["to"]]
        sizeToReuse = abs(fromGroup.getAddress() - toGroup.getAddress()) / fromGroup.getDataTypeSize()
    else:
        print("Groups for size reuse not found: {} {}".format(sizeReuseRule["from"], sizeReuseRule["to"]))
        sizeReuseRule["folder"] = None

    for group_id, group in found_groups.items():
        if group.getFolderName() == sizeReuseRule["folder"]:
            sizes = group.getSizes()
            group.setSizes(sizes["x"], sizeToReuse)

        for_export["maps"].append({
            "name": group.getName(),
            "key": group.getId(),
            "sizes": dict(group.getSizes()),
            "address": utils.clean_hex(group.getAddress().getOffset() - 0x80000000)
        })

    print(json.JSONEncoder().encode(for_export))
    output_dir = getScriptArgs()[0]
    with open(os.path.join(output_dir, scriptcode + ".json"), 'w') as jsonFile:
        json.dump(for_export, jsonFile)

if __name__ == '__main__':
    run()
