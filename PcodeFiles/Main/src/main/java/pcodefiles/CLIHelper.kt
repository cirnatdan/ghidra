package pcodefiles

import ghidra.app.script.GhidraScriptUtil
import ghidra.app.services.ConsoleService
import ghidra.framework.model.ProjectManager
import ghidra.framework.options.SaveState
import ghidra.program.model.lang.LanguageService
import ghidra.util.task.TaskMonitor
import pcodefiles.analysis.WinOLSAnalyzer
import pcodefiles.console.CLIConsole
import pcodefiles.console.HeadlessOptions
import java.io.File

class CLIHelper(
    private val languageService: LanguageService,
    private val projectManager: ProjectManager
) {
    fun run(args: Array<String>) {
        println("CLI")
        val options = HeadlessOptions()

        parseOptions(options, args)
        println(options.winOLSScript)
        println(options.exampleFile)
        println(options.inputFiles)
        println(options.outputDir)

        val monitor = TaskMonitor.DUMMY
        val analyzer = WinOLSAnalyzer(CLIConsole(), monitor, reuseAnalysis = false, languageService)
        val winOLSPM = WinOLSProjectManager(
            projectManager,
            CLIConsole(),
            false
        )
        GhidraScriptUtil.acquireBundleHostReference();
        monitor.message = "Parse winolsscript file"
        val project = winOLSPM.openProject(options.winOLSScript!!)!!
        project.setSaveableData("analysis_report", SaveState())
        val report = project.getSaveableData("analysis_report")

        try {
            analyzer.analyzeExampleFirmware(project, options.winOLSScript!!, options.exampleFile!!, options.outputDir)

            for (file in options.inputFiles) {
                analyzer.runAnalysis(project, file, options.outputDir!!)
                val scriptcode = report.getString(file.name + "_scriptcode", "")
                if ("" != scriptcode) {
                    analyzer.renameFile(file, scriptcode)
                }
            }

        } catch (ex: Exception) {
            println(ex.message)
            ex.printStackTrace()
        }
    }

    private fun parseOptions(options: HeadlessOptions, args: Array<String>) {
        var skipNext = false
        var inputFiles = true
        args@ for (i in args.indices)  {
            if (skipNext) {
                skipNext = false
                continue
            }
            if (inputFiles && !args[i].startsWith("--")) {
                options.inputFiles.add(File(args[i]))
                continue
            }
            inputFiles = false
            when(args[i]) {
                "--script" -> {
                    options.winOLSScript = File(args[i + 1])
                    skipNext = true
                    continue@args
                }
                "--example" -> {
                    options.exampleFile = File(args[i + 1])
                    skipNext = true
                    continue@args
                }
                "--inputFiles" -> {
                    inputFiles = true
                    continue@args
                }
                "--outputDir" -> {
                    options.outputDir = File(args[i + 1])
                    skipNext = true
                    continue@args
                }
            }
        }
    }
}