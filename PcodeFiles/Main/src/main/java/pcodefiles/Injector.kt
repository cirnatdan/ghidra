package pcodefiles

import docking.framework.SplashScreen
import ghidra.framework.model.ProjectManager
import ghidra.framework.model.ToolChest
import ghidra.framework.project.DefaultProjectManager
import ghidra.util.SystemUtilities
import javax.swing.ToolTipManager

class Injector {
    val applicationConfiguration by lazy {
        createApplicationConfiguration()
    }

    val mainHelper by lazy {
        createMainHelper()
    }

    private val toolTipManager by lazy {
        createToolTipManager()
    }

    private val winOLSTool by lazy {
        createWinOLSTool()
    }

    private val projectManager by lazy {
        createProjectManager()
    }

    private val frontEndPlugin by lazy {
        createFrontEndPlugin()
    }

    private fun updateSplashScreenStatusMessage(message: String) {
        SystemUtilities.runSwingNow { SplashScreen.updateSplashScreenStatus(message) }
    }

    private fun createMainHelper(): MainHelper {
        return MainHelper(toolTipManager, winOLSTool, frontEndPlugin)
    }

    private fun createToolTipManager(): ToolTipManager {
        return ToolTipManager.sharedInstance()
    }

    private fun createApplicationConfiguration(): PcodeFilesApplicationConfiguration {
        val configuration = PcodeFilesApplicationConfiguration()
        configuration.taskMonitor = createStatusReportingTaskMonitor()
        return configuration
    }

    private fun createStatusReportingTaskMonitor(): StatusReportingTaskMonitor {
        return StatusReportingTaskMonitor()
    }

    private fun createWinOLSTool(): WinOLSTool {
        updateSplashScreenStatusMessage("Creating front end tool...")
        return WinOLSTool(projectManager)
    }

    private fun createProjectManager(): ProjectManager {
        class GhidraProjectManager : DefaultProjectManager() {
            // this exists just to allow access to the constructor
            override fun addDefaultTools(tools: ToolChest) {}
        }
        updateSplashScreenStatusMessage("Creating project manager...")
        return GhidraProjectManager()
    }

    private fun createFrontEndPlugin(): FrontEndPlugin {
        return FrontEndPlugin(winOLSTool)
    }
}