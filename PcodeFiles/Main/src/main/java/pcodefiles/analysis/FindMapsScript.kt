package pcodefiles.analysis

import com.google.gson.Gson
import ghidra.app.script.GhidraScript
import ghidra.framework.options.SaveState
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer32DataType
import ghidra.program.model.lang.Register
import ghidra.program.model.scalar.Scalar
import pcodefiles.model.Group
import java.io.File
import kotlin.math.abs

class FindMapsScript(
    private val report: SaveState
): GhidraScript(), Utils {
    override fun run() {
        val startOfData = findDataSector()
        if (startOfData == null) {
            println("Could not find data sector!")
            val badFiles = report.getStrings("badFiles", arrayOf()).toMutableList()
            badFiles.add(currentProgram.name)
            report.putStrings("badFiles", badFiles.toTypedArray())
            return
        }

        println("Data sector starts at $startOfData")
        val softwareVersion = getSoftwareVersion(getScriptcodeAddress(startOfData)!!)
        val scriptcode = convertScriptcode(softwareVersion)
        println("Scriptcode: $scriptcode")
        val listing = currentProgram.listing

        val mapsForExport = mutableListOf<Map<String,Any?>>()

        val foundGroups = hashMapOf<String,Group>()
        val notFoundGroups = arrayListOf<String>()

        File(scriptArgs[0], "code.patterns").forEachLine {
            System.out.println(it)
            val line = it.trim().split("::")
            val group = Group(line[0])
            group.name = line[1]
            group.setGroupType(line[2].toInt())
            group.setDataOrg(line[3])
            val initialOffset = line[4].toInt()
            group.folderName = line[5]
            val suboffset = line[6].toInt()
            val patterns = line.drop(7) // take last elements

            var offsets = setOf<Long>()

            var closestOffset: Long? = null
            patterns.forEach { pattern ->
                val codeLocation = findPattern(pattern)
                if (codeLocation == null) {
                    println("${group.id} code could not be found with pattern $pattern")
                    return@forEach
                }
                println("${group.id} code found at $codeLocation")
                disassemble(codeLocation)

                val instruction = listing.getInstructionAt(codeLocation)
                if (instruction == null) {
                    println("Instruction could not be disassembled for pattern $pattern")
                    return@forEach
                }
                val input = instruction.inputObjects
                if (input[1] !is Register){
                    input.reverse()
                }

                if ((input[1] as Register).name != "a9") {
                    println("Could not find offset for ${group.id}".format(group.id))
                    return@forEach
                }
                val offset = input[0] as Scalar
                println("Found offset $offset at 0x${instruction.address}")

                offsets = offsets.plus(offset.value)
                closestOffset = offset.value // initial value
            }

            if (offsets.isEmpty()) {
                println("No code or offsets found for group ${group.id}")
                notFoundGroups.add(group.id)
                return@forEachLine
            }

            val probableAddress = hashMapOf<Long, Address>()
            offsets.forEach { offset ->
                // compute size
                val dataPtr = startOfData.add(offset)
                var dataAddress = getDataAt(dataPtr)
                if (dataAddress == null)
                    dataAddress = createData(dataPtr, Pointer32DataType())
                probableAddress[offset] = dataAddress.value as Address
                val size = computeMapSize(startOfData, offset, group.dataTypeSize)
                println("Found probable ${group.name} at $dataAddress with size $size")
                println("$offset, $initialOffset, $closestOffset")
                if (abs(offset - initialOffset) < abs(closestOffset!! - initialOffset))
                    closestOffset = offset
            }

            println("Closest offset is " + Integer.toHexString(closestOffset!!.toInt()))
            group.setSizes(1, computeMapSize(startOfData, closestOffset!!, group.dataTypeSize).toInt())
            group.address = probableAddress[closestOffset]
            if (suboffset > 0) {
                group.address = group.address!!.add(suboffset.toLong())
            }
            foundGroups[group.id] = group
        }

        val sizeReuseRule = readSizeReuse(File(scriptArgs[0],"size.reuse")).toMutableMap()
        var sizeToReuse: Long? = null
        if (sizeReuseRule["from"] in foundGroups && sizeReuseRule["to"] in foundGroups) {
            val fromGroup = foundGroups[sizeReuseRule["from"]]
            val toGroup = foundGroups[sizeReuseRule["to"]]
            sizeToReuse = abs(fromGroup!!.address!!.offset - toGroup!!.address!!.offset) / fromGroup.dataTypeSize
        } else {
            println("Groups for size reuse not found: ${sizeReuseRule["from"]} ${sizeReuseRule["to"]}")
            sizeReuseRule["folder"] = ""
        }

        for (g in foundGroups) {
            val group = g.value
            if (group.folderName == sizeReuseRule["folder"]) {
                val sizes = group.sizes
                group.setSizes(sizes["x"]!!, sizeToReuse!!.toInt())
            }

            mapsForExport.add(mapOf(
                "name" to group.name,
                "key" to  group.id,
                "sizes" to group.sizes,
                "address" to "0x" + Integer.toHexString((group.address!!.offset-0x80000000).toInt())
            ))
        }

        val forExport = mutableMapOf(
            "scriptcode" to scriptcode,
            "softwaresize" to Integer.toHexString(programFile.length().toInt()),
            "maps" to mapsForExport
        )

        val gson = Gson()
        println(gson.toJson(forExport))

        report.putStrings(currentProgram.name, notFoundGroups.toTypedArray())
        report.putString("${currentProgram.name}_scriptcode", scriptcode)
        if (notFoundGroups.size < (foundGroups.size + notFoundGroups.size) / 2) {
            val okFiles = report.getStrings("okFiles", arrayOf()).toMutableList()
            okFiles.add(currentProgram.name)
            report.putStrings("okFiles", okFiles.toTypedArray())
        } else {
            val badFiles = report.getStrings("badFiles", arrayOf()).toMutableList()
            badFiles.add(currentProgram.name)
            report.putStrings("badFiles", badFiles.toTypedArray())
        }

        val outputDir = scriptArgs[0]
        File(outputDir, "$scriptcode.json").writeText(gson.toJson(forExport))
    }

    private fun readSizeReuse(file: File): Map<String,String> {
        var sizeReuse = mapOf<String,String>("from" to "", "to" to "")
        if (!file.exists()) {
            return sizeReuse
        }
        file.forEachLine {
            val line = it.trim().split("::")
            sizeReuse = mapOf(
                "from" to line[0],
                "to" to  line[1],
                "folder" to line[2]
            )
        }

        return sizeReuse
    }

    private fun findPattern(pattern: String): Address? {
        val matches = findBytes(toAddr(0x80004000), pattern, 2)
        if (matches.isEmpty())
            return null
        if (matches.size <= 2)
            return matches[0]
        else if(matches.size > 2)
            throw RuntimeException("not an exact match, found ${matches.size}")
        return null
    }
}