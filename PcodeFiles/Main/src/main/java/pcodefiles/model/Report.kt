package pcodefiles.model

import ghidra.framework.options.SaveState

class Report (private val report: SaveState) {
    val okFiles: Array<String> by lazy {
        report.getStrings("okFiles", arrayOf())
    }

    val badFiles: Array<String> by lazy {
        report.getStrings("badFiles", arrayOf())
    }

    val okPercentage by lazy {
        if (okFiles.size + badFiles.size > 0)
            okFiles.size / (okFiles.size + badFiles.size) * 100
        else 0
    }

    fun getScriptCode(file: String): String {
        return report.getString(file + "_scriptcode", "NOTFOUND")
    }

    fun getNotFoundGroups(file: String): Array<out String>? {
        return report.getStrings(file, arrayOf())
    }
}