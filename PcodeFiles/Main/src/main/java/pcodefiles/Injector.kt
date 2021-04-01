package pcodefiles

import docking.framework.SplashScreen
import ghidra.app.plugin.core.console.ConsolePlugin
import ghidra.app.services.ConsoleService
import ghidra.framework.model.ProjectManager
import ghidra.framework.model.ToolChest
import ghidra.framework.project.DefaultProjectManager
import ghidra.program.model.lang.LanguageService
import ghidra.program.util.DefaultLanguageService
import ghidra.util.SystemUtilities
import pcodefiles.action.ProcessFilesActionListener
import pcodefiles.ui.WinOLSPanel
import javax.swing.ToolTipManager

class Injector {
    val applicationConfiguration by lazy {
        createApplicationConfiguration()
    }

    val guiHelper by lazy {
        createGUIHelper()
    }

    val cliHelper by lazy {
        createCLIHelper()
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

    private val winOLSPanel by lazy {
        createWinOLSPanel()
    }

    private val processFilesActionListener by lazy {
        createProcessFilesActionListener()
    }

    private val languageService by lazy {
        createLanguageService()
    }

    private val consoleService by lazy {
        createConsoleService()
    }

    private val consolePlugin by lazy {
        createConsolePlugin()
    }

    private fun createConsolePlugin(): ConsolePlugin {
        return ConsolePlugin(winOLSTool)
    }

    private fun createConsoleService(): ConsoleService {
        return winOLSTool.getService(ConsoleService::class.java)
    }

    private fun updateSplashScreenStatusMessage(message: String) {
        SystemUtilities.runSwingNow { SplashScreen.updateSplashScreenStatus(message) }
    }

    private fun createGUIHelper(): GUIHelper {
        return GUIHelper(toolTipManager, winOLSTool, frontEndPlugin)
    }

    private fun createCLIHelper(): CLIHelper {
        class HeadlessPM : DefaultProjectManager() {
            // this exists just to allow access to the constructor
        }
        return CLIHelper(languageService, HeadlessPM())
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
        return FrontEndPlugin(winOLSTool, winOLSPanel)
    }

    private fun createWinOLSPanel(): WinOLSPanel {
        return WinOLSPanel(processFilesActionListener)
    }

    private fun createProcessFilesActionListener(): ProcessFilesActionListener {
        return ProcessFilesActionListener(winOLSTool, projectManager, languageService)
    }

    private fun createLanguageService(): LanguageService {
        return DefaultLanguageService.getLanguageService()
    }
}