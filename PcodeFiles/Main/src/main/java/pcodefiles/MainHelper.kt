package pcodefiles

import docking.framework.SplashScreen
import ghidra.GhidraRun
import ghidra.framework.data.DomainObjectAdapter
import ghidra.framework.model.ProjectLocator
import ghidra.framework.plugintool.dialog.ExtensionUtils
import ghidra.framework.store.LockException
import ghidra.program.database.ProgramDB
import ghidra.util.Msg
import ghidra.util.Swing
import ghidra.util.SystemUtilities
import ghidra.util.exception.UsrException
import ghidra.util.task.TaskLauncher
import java.io.File
import javax.swing.ToolTipManager

class MainHelper(
    private val toolTipManager: ToolTipManager,
    private val tool: WinOLSTool,
    private val frontEndPlugin: FrontEndPlugin
) {
    fun run(args: Array<String>) {
        initializeTooltips()
        ExtensionUtils.cleanupUninstalledExtensions()

        // Allows handling of old content which did not have a content type property
        DomainObjectAdapter.setDefaultContentClass(ProgramDB::class.java)

        SystemUtilities.runSwingLater {
            val projectPath: String? = processArguments(args)
            tool.init(frontEndPlugin)
            openProject(projectPath)
        }
    }

    private fun processArguments(args: Array<String>): String? {
        //TODO remove this special handling when possible
        var args = args
        if (args.size == 1 && (args[0].startsWith("-D") || args[0].indexOf(" -D") >= 0)) {
            args = args[0].split(" ").toTypedArray()
        }
        var projectPath: String? = null
        for (arg in args) {
            if (arg.startsWith("-D")) {
                val split = arg.substring(2).split("=").toTypedArray()
                if (split.size == 2) {
                    System.setProperty(split[0], split[1])
                }
            } else {
                projectPath = arg
            }
        }
        return projectPath
    }

    private fun initializeTooltips() {
        val currentDelay = toolTipManager.dismissDelay
        toolTipManager.dismissDelay = currentDelay * 2
    }

    /**
     * Open the specified project or the last active project if projectPath is null.
     * Makes the project window visible.
     * @param projectPath optional project to be opened (specifies project file)
     */
    private fun openProject(projectPath: String?) {
        var reopen = true
        var projectLocator: ProjectLocator? = null
        if (projectPath != null) {
            val projectFile = File(projectPath)
            val name = projectFile.name
            if (!name.endsWith(ProjectLocator.getProjectExtension())) {
                Msg.showInfo(
                    GhidraRun::class.java, null, "Invalid Project",
                    "The specified file is not a project file: $projectPath"
                )
            } else {
                projectLocator = ProjectLocator(projectFile.parent, name)
                reopen = false
            }
        }
        tool.isVisible = true
        projectLocator?.let { openProject(tool, it, reopen) }
    }

    private fun openProject(tool: WinOLSTool, projectLocator: ProjectLocator, reopen: Boolean) {
        SplashScreen.updateSplashScreenStatus(
            (if (reopen) "Reopening" else "Opening") + " project: " + projectLocator.name
        )
        val r = Runnable { doOpenProject(tool, projectLocator, reopen) }
        TaskLauncher.launchModal("Opening Project", Runnable { Swing.runNow(r) })
    }

    private fun doOpenProject(tool: WinOLSTool, projectLocator: ProjectLocator, reopen: Boolean) {
        try {
            val pm = tool.projectManager
            val activeProject = pm.openProject(projectLocator, true, false) ?: return
            tool.setActiveProject(activeProject)
            val repository = activeProject.repository
            if (repository != null && !repository.isConnected) {
                Msg.showInfo(
                    GhidraRun::class.java, null, "Working Off-Line ",
                    "Even though you are not connected to the Ghidra Server,\n" +
                            "you can still work off-line on checked out files or private files.\n" +
                            "You can also try reconnecting to the server by selecting the connect\n" +
                            "button on the Ghidra Project Window.\n \n" +
                            "See the Ghidra Help topic 'Project Repository' for troubleshooting\n" +
                            "a failed connection."
                )
            }
        } catch (t: Throwable) {
            if (t is UsrException) {
                if (t is LockException) {
                    Msg.showInfo(
                        GhidraRun::class.java, null, "Project is Locked",
                        ("Can't open project: " + projectLocator.toString() +
                                "\nProject is already locked")
                    )
                } else {
                    Msg.showInfo(
                        GhidraRun::class.java, null, "Project Open Failed",
                        ("Failed to " + (if (reopen) "reopen last" else "open") + " project: " +
                                projectLocator.toString() + "\n\n" + t.javaClass.simpleName +
                                ": " + t.message)
                    )
                }
            } else {
                Msg.showError(
                    GhidraRun::class.java, null, "Project Open Failed",
                    ("Failed to " + (if (reopen) "reopen last" else "open") + " project: " +
                            projectLocator.toString() + "\n\n" + t.javaClass.simpleName + ": " +
                            t.message),
                    t
                )
            }
            tool.setActiveProject(null)
        }
    }
}