package pcodefiles

import ghidra.app.services.ConsoleService
import ghidra.framework.GenericRunInfo
import ghidra.framework.model.Project
import ghidra.framework.model.ProjectLocator
import ghidra.framework.model.ProjectManager
import ghidra.framework.store.LockException
import ghidra.util.Msg
import ghidra.util.NotOwnerException
import ghidra.util.exception.NotFoundException
import java.io.File
import java.io.IOException

class WinOLSProjectManager (
    private val projectManager: ProjectManager,
    private val consoleService: ConsoleService,
    private val reuseAnalysis: Boolean,
) {
    fun openProject(winOLSScript: File): Project? {
        consoleService.println("Opening project " + winOLSScript.absolutePath)
        val projectLocator = ProjectLocator(GenericRunInfo.getProjectsDirPath(), winOLSScript.name)
        if (projectManager.getActiveProject() != null) {
            projectManager.activeProject.close()
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
}