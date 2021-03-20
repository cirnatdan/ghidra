package pcodefiles.analysis

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import ghidra.app.script.GhidraScript
import ghidra.framework.options.SaveState
import ghidra.program.model.address.Address
import ghidra.program.model.symbol.Symbol
import pcodefiles.model.Group
import pcodefiles.model.GroupType
import java.io.File

class MatchMapsScript(
    private val winOLSParseResult: SaveState,
    private val outputDir: File?
): GhidraScript(), Utils {
    override fun run() {
        val gson = Gson()
        println(winOLSParseResult.getString("winOLS_groups", ""))

        val foundMaps = mutableListOf<Pair<Group,Address>>()
        val notFoundMaps = mutableListOf<Triple<Group,Address,Symbol?>>()

        gson.fromJson<List<Map<String, Any>>>(
            winOLSParseResult.getString("winOLS_groups", ""),
            object: TypeToken<List<Map<String,Any>>>() {}.type
        ).forEach {
            val group = Group.fromMap(it)
            matchMap(group, foundMaps, notFoundMaps)
        }

        println("Found:")
        foundMaps.forEach { entry ->
            println("%s %s".format(entry.first.id, entry.second))
        }
        println("Not Found:")
        notFoundMaps.forEach { entry ->
            println("%s %s, closest: %s".format(
                entry.first.id,
                entry.second,
                if (entry.third != null) entry.third!!.address else "not found"
            ))
        }

        val listing = currentProgram.listing
        val dataSectorAddress = findDataSector()!!
        print("Data sector starts at: %s".format(dataSectorAddress))

        val lines = mutableListOf<String>()
        foundMaps.forEach {
            val group = it.first
            val address = it.second

            val mapOffset = getMapOffset(dataSectorAddress, address)
            println("%s offset: 0x%x".format(group.id, mapOffset))
            val line = mutableListOf(
                group.id,
                group.name,
                group.groupType!!.value.toString(),
                group.dataOrg.toString(),
                mapOffset.toString(),
                group.folderName,
                (-1).toString(),  // no suboffset
            )

            val patterns = mutableListOf<List<String>>()
            var codeAddress = findOffsetInCode(listing.getInstructions(toAddr(0x80004000), true), mapOffset)
            while (codeAddress != null) {
                line.add(getInstructionsPattern(listing.getCodeUnits(codeAddress, true)))
                patterns.add(getInstructionsPatternForIDAPro(listing.getCodeUnits(codeAddress, true)))
                codeAddress = findOffsetInCode(listing.getInstructions(codeAddress.add(16), true), mapOffset)
            }
            lines.add(line.joinToString("::"))
            winOLSParseResult.putStrings(
                group.id + "_patterns",
                patterns.map { p -> p.joinToString(" ") }.toTypedArray()
            )
        }

        notFoundMaps.forEach {
            val group = it.first
            val headAddress = it.second
            val address = it.third!!.address

            val mapOffset = getMapOffset(dataSectorAddress, address)
            println("%s offset: 0x%x".format(group.id, mapOffset))
            val mapSubOffset = headAddress.subtract(address)
            println("%s suboffset: 0x%x".format(group.id, mapSubOffset))
            val line = mutableListOf(
                group.id,
                group.name,
                group.groupType!!.value.toString(),
                group.dataOrg.toString(),
                mapOffset.toString(),
                group.folderName,
                mapSubOffset.toString(),  // no suboffset
            )

            val patterns = mutableListOf<List<String>>()
            var codeAddress = findOffsetInCode(listing.getInstructions(toAddr(0x80004000), true), mapOffset)
            while (codeAddress != null) {
                val foundSuboffset = hasSuboffsetInCode(listing.getInstructions(codeAddress, true), mapSubOffset)
                if (foundSuboffset) {
                    line.add(getInstructionsPattern(listing.getCodeUnits(codeAddress, true)))
                    patterns.add(getInstructionsPatternForIDAPro(listing.getCodeUnits(codeAddress, true)))
                    break
                }
                codeAddress = findOffsetInCode(listing.getInstructions(codeAddress!!.add(16), true), mapOffset)
            }
            if (line.size > 7) {
                winOLSParseResult.putStrings(
                    group.id + "_patterns",
                    patterns.map { p -> p.joinToString(" ") }.toTypedArray()
                )
                lines.add(line.joinToString("::"))
            }
        }

        if (outputDir != null)
            File(outputDir, "code.patterns").printWriter().use { out ->
                lines.forEach {
                    out.println(it)
                }
            }
    }

    private fun matchMap(
        group: Group,
        foundMaps: MutableList<Pair<Group, Address>>,
        notFoundMaps: MutableList<Triple<Group,Address,Symbol?>>
    ) {
        var address = toAddr(group.address!!.offset)
        if (group.groupType == GroupType.GROUP_TYPE_LIST) {
            address = address
        } else {
            address = address.add(group.dataTypeSize.toLong())
        }

        val symbol = getSymbolAt(address)
        if (symbol == null) {
            val nearSymbol = getSymbolBefore(address)
            notFoundMaps.add(Triple<Group,Address,Symbol?>(group,address,nearSymbol))
        } else {
            foundMaps.add(Pair(group, address))
        }
    }
}