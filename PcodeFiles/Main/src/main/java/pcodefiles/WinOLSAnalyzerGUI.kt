package pcodefiles

import generic.jar.ResourceFile
import generic.stl.Pair
import generic.util.Path
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.script.GhidraScriptUtil
import ghidra.app.script.GhidraState
import ghidra.app.services.ConsoleService
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.BinaryLoader
import ghidra.framework.GenericRunInfo
import ghidra.framework.model.Project
import ghidra.framework.model.ProjectLocator
import ghidra.framework.model.ProjectManager
import ghidra.framework.store.LockException
import ghidra.program.model.lang.Language
import ghidra.program.model.lang.LanguageID
import ghidra.program.model.listing.Program
import ghidra.program.util.DefaultLanguageService
import ghidra.util.InvalidNameException
import ghidra.util.Msg
import ghidra.util.NotOwnerException
import ghidra.util.exception.CancelledException
import ghidra.util.exception.DuplicateNameException
import ghidra.util.exception.NotFoundException
import ghidra.util.exception.VersionException
import ghidra.util.task.TaskMonitor
import java.io.File
import java.io.IOException
import java.util.*

class WinOLSAnalyzerGUI(
    private val projectManager: ProjectManager,
    private val consoleService: ConsoleService,
    private val monitor: TaskMonitor,
    private val reuseAnalysis: Boolean
) {
    private val language: Language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("tricore:LE:32:tc176x"))
    fun openProject(winOLSScript: File): Project? {
        consoleService.println("Opening project " + winOLSScript.absolutePath)
        val projectLocator = ProjectLocator(GenericRunInfo.getProjectsDirPath(), winOLSScript.name)
        if (AppInfo.getActiveProject() != null) {
            AppInfo.getActiveProject().close()
        }
        if (!reuseAnalysis) {
            if (projectManager.projectExists(projectLocator)) {
                projectManager.deleteProject(projectLocator)
            }
        }
        var project: Project? = null
        project = if (!projectManager.projectExists(projectLocator)) {
            try {
                projectManager.createProject(projectLocator, null, true)
            } catch (e: IOException) {
                Msg.error(this, "Project creation Exception: " + e.message, e)
                return null
            }
        } else {
            try {
                projectManager.openProject(projectLocator, true, true)
            } catch (e: NotFoundException) {
                Msg.error(this, "Project open Exception: " + e.message, e)
                return null
            } catch (e: NotOwnerException) {
                Msg.error(this, "Project open Exception: " + e.message, e)
                return null
            } catch (e: LockException) {
                Msg.error(this, "Project open Exception: " + e.message, e)
                return null
            }
        }
        AppInfo.getFrontEndTool().setActiveProject(project)
        return project
    }

    @Throws(Exception::class)
    fun analyzeExampleFirmware(
        project: Project,
        winOLSScript: File,
        exampleFile: List<File>,
        outputDir: File
    ): Program {
        consoleService.println("Start analysis for " + winOLSScript.absolutePath)
        val exampleProgram: Program
        val rootFolder = project.projectData.rootFolder
        if (reuseAnalysis && null != rootFolder.getFile(exampleFile[0].name)) {
            exampleProgram = rootFolder.getFile(exampleFile[0].name).getDomainObject(
                this, true, false, monitor
            ) as Program
        } else {
            exampleProgram = AutoImporter.importByUsingSpecificLoaderClassAndLcs(
                exampleFile[0],
                project.projectData.rootFolder,
                BinaryLoader::class.java,
                object : LinkedList<Pair<String?, String?>?>() {
                    init {
                        add(Pair("-loader-baseAddr", "0x80000000"))
                    }
                },
                language,
                language.defaultCompilerSpec,
                this,
                MessageLog(),
                monitor
            )
            monitor.message = "Creating data structure labels"
            runScript("create_data_labels.py", arrayOf(), exampleProgram)
            monitor.message = "Scanning for possible offsets"
            runScript("analyze_possible_offsets.py", arrayOf(), exampleProgram)
            if (exampleProgram.canSave()) exampleProgram.save("analyzed_possible_offsets", monitor)
        }
        val transactionId = exampleProgram.startTransaction("analysis")
        val analysisOptions = exampleProgram.getOptions(Program.ANALYSIS_PROPERTIES)
        val analysisMgr = AutoAnalysisManager.getAnalysisManager(exampleProgram)
        analysisOptions.setBoolean("DWARF", false)
        analysisOptions.setBoolean("ARM Symbol", false)
        analysisOptions.setBoolean("Embedded Media", false)
        analysisMgr.initializeOptions()
        exampleProgram.endTransaction(transactionId, true)
        if (exampleProgram.canSave()) exampleProgram.save("analysis", monitor)
        monitor.message = "Parsing winolsskript"
        runScript("parse_winolsscript.py", arrayOf(winOLSScript.absolutePath, outputDir.absolutePath), exampleProgram)
        return exampleProgram
    }

    fun runAnalysis(project: Project?, inputFiles: List<File>, outputDir: File) {
        val fileNames = ArrayList<String>()
        try {
            for (file in inputFiles) {
                monitor.message = "Analyzing " + file.name
                fileNames.add(file.name)
                val program = AutoImporter.importByUsingSpecificLoaderClassAndLcs(
                    file,
                    null,
                    BinaryLoader::class.java,
                    object : LinkedList<Pair<String?, String?>?>() {
                        init {
                            add(Pair("-loader-baseAddr", "0x80000000"))
                        }
                    },
                    language,
                    language.defaultCompilerSpec,
                    this,
                    MessageLog(),
                    monitor
                )
                if (program == null) {
                    Msg.error(this, "Program " + file.name + " could not be imported")
                } else {
                    consoleService.println("Looking for maps in " + file.name)
                    program.isTemporary = true
                    runScript("find_maps.py", arrayOf(outputDir.absolutePath), program)
                }
            }
        } catch (e: NotFoundException) {
            Msg.error(this, "Project open Exception: " + e.message, e)
        } catch (e: NotOwnerException) {
            Msg.error(this, "Project open Exception: " + e.message, e)
        } catch (e: LockException) {
            Msg.error(this, "Project open Exception: " + e.message, e)
        } catch (e: IOException) {
            Msg.error(this, "Program import Exception: " + e.message, e)
        } catch (e: InvalidNameException) {
            Msg.error(this, "Program import Exception: " + e.message, e)
        } catch (e: CancelledException) {
            Msg.error(this, "Program import Exception: " + e.message, e)
        } catch (e: VersionException) {
            Msg.error(this, "Program import Exception: " + e.message, e)
        } catch (e: DuplicateNameException) {
            Msg.error(this, "Program import Exception: " + e.message, e)
        } catch (e: IllegalAccessException) {
            Msg.error(this, "Script run Exception: " + e.message, e)
        } catch (e: InstantiationException) {
            Msg.error(this, "Script run Exception: " + e.message, e)
        } catch (e: ClassNotFoundException) {
            Msg.error(this, "Script run Exception: " + e.message, e)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @Throws(Exception::class)
    private fun runScript(scriptName: String, args: Array<String>, exampleProgram: Program) {
        Msg.info(this, "Running script $scriptName")
        val scriptFile = ResourceFile(
            Path.fromPathString(Path.GHIDRA_HOME + "/../PcodeFiles/Main/ghidra_scripts/" + scriptName).getFile(false)
        )
        val script = Objects.requireNonNull(GhidraScriptUtil.getProvider(scriptFile))
            .getScriptInstance(scriptFile, consoleService.stdOut)
        script.scriptArgs = args
        script.execute(
            GhidraState(AppInfo.getFrontEndTool(), AppInfo.getActiveProject(), exampleProgram, null, null, null),
            monitor,
            consoleService.stdOut
        )
    }

}