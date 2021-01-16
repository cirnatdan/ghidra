/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pcodefiles;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.main.*;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.Swing;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskLauncher;

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Helper class to manage actions on the File menu.
 */
class FileActionManager {

	private final static int NEW_ACCELERATOR = KeyEvent.VK_N;
	private final static int OPEN_ACCELERATOR = KeyEvent.VK_O;
	private final static int CLOSE_ACCELERATOR = KeyEvent.VK_W;
	private final static int SAVE_ACCELERATOR = KeyEvent.VK_S;
	private final static String LAST_SELECTED_PROJECT_DIRECTORY = "LastSelectedProjectDirectory";

	private static final String DISPLAY_DATA = "DISPLAY_DATA";

	private WinOLSTool tool;
	private FrontEndPlugin plugin;

	private GhidraFileChooser fileChooser;

	private boolean firingProjectOpened;

	FileActionManager(FrontEndPlugin plugin) {
		this.plugin = plugin;
		tool = (WinOLSTool) plugin.getTool();
	}

	/**
	 * Open an existing project, using a file chooser to specify where the
	 * existing project folder is stored.
	 * @param projectLocator the project locator
	 * @return true if the project was opened
	 */
	final boolean doOpenProject(ProjectLocator projectLocator) {
		String status = "Opened project: " + projectLocator.getName();
		Project project = null;
		boolean openStatus = false;
		try {
			// first close the active project (if there is one)
			// but if user cancels operation, don't continue
			if (!closeProject(false)) {
				return true;
			}
			ProjectManager pm = plugin.getProjectManager();
			project = pm.openProject(projectLocator, true, false);
			if (project == null) {
				status = "Error opening project: " + projectLocator.toString();
			}
			else {
				firingProjectOpened = true;
				tool.setActiveProject(project);
				openProjectAndNotify(project);
				openStatus = true;
				firingProjectOpened = false;
			}
		}
		catch (NotFoundException nfe) {
			status = "Project not found for " + projectLocator.toString();
			Msg.showInfo(getClass(), tool.getToolFrame(), "Error Opening Project", status);
		}
		catch (NotOwnerException e) {
			status = "Cannot open project: " + e.getMessage();
			Msg.showError(this, null, "Not Project Owner", "Cannot open project " + projectLocator +
				"\n" + e.getMessage() +
				"\n \nEach user must create their own project. If needed, another user's project may be viewed\n" +
				"and files copied, using the View Other action from your own open project.  Alternatively, \n" +
				"creating a \"Shared Project\" will allow a group of users to use a shared server-based repository.");
		}
		catch (LockException e) {
			status = "Project is already open for update: " + projectLocator.toString();
			Msg.showError(this, null, "Open Project Failed", status);
		}
		catch (Exception e) {
			status = "Error opening project: " + projectLocator.toString();
			Msg.showError(this, null, "Open Project Failed", status, e);
		}
		finally {
			// update our list of recent projects
			plugin.rebuildRecentMenus();
		}

		if (!openStatus) {
			Msg.error(this, status);
		}
		else {
			Msg.info(this, status);
		}
		return openStatus;
	}

	/**
	 * Obtain domain objects from files and lock.  If unable to lock 
	 * one or more of the files, none are locked and null is returned.
	 * @param files the files
	 * @return locked domain objects, or null if unable to lock
	 * all domain objects.
	 */
	private DomainObject[] lockDomainObjects(List<DomainFile> files) {
		DomainObject[] objs = new DomainObject[files.size()];
		int lastIndex = 0;
		boolean locked = true;
		while (lastIndex < files.size()) {
			try {
				objs[lastIndex] = files.get(lastIndex).getDomainObject(this, false, false, null);
			}
			catch (Throwable t) {
				Msg.error(this, "Failed to aqcuire domain object instance", t);
				locked = false;
				break;
			}
			if (!objs[lastIndex].lock(null)) {
				String title = "Exit Ghidra";
				StringBuffer buf = new StringBuffer();
				UndoableDomainObject udo = (UndoableDomainObject) objs[lastIndex];
				buf.append("The File " + files.get(lastIndex).getPathname() +
					" is currently being modified by the\n");
				buf.append("the following actions:\n \n");
				Transaction t = udo.getCurrentTransaction();
				List<String> list = t.getOpenSubTransactions();
				Iterator<String> it = list.iterator();
				while (it.hasNext()) {
					buf.append("\n     ");
					buf.append(it.next());
				}
				buf.append("\n \n");
				buf.append(
					"You may exit Ghidra, but the above action(s) will be aborted and all\n");
				buf.append("changes made by those actions (and all changes made since those\n");
				buf.append("actions started),will be lost!  You will still have the option of \n");
				buf.append("saving any changes made before those actions began.\n \n");
				buf.append("Do you want to abort the action(s) and exit Ghidra?");

				int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title,
					buf.toString(), "Exit Ghidra", OptionDialog.WARNING_MESSAGE);

				if (result == OptionDialog.CANCEL_OPTION) {
					locked = false;
					objs[lastIndex].release(this);
					break;
				}
				udo.forceLock(true, null);
			}
			++lastIndex;
		}
		if (!locked) {
			//skip the last one that could not be locked...
			for (int i = 0; i < lastIndex; i++) {
				objs[i].unlock();
				objs[i].release(this);
			}
			return null;
		}
		return objs;
	}

	/**
	 * menu listener for File | Close Project...
	 * <p>
	 * This method will always save the FrontEndTool and project, but not the data unless 
	 * <tt>confirmClose</tt> is called.
	 * 
	 * @param isExiting true if we are closing the project because 
	 * Ghidra is exiting
	 * @return false if user cancels the close operation
	 */
	boolean closeProject(boolean isExiting) {
		// if there is no active project currently, ignore request
		Project activeProject = plugin.getActiveProject();
		if (activeProject == null) {
			return true;
		}

		// check for any changes since last saved
		PluginTool[] runningTools = activeProject.getToolManager().getRunningTools();
		for (PluginTool runningTool : runningTools) {
			if (!runningTool.canClose(isExiting)) {
				return false;
			}
		}

		boolean saveSuccessful = saveChangedData(activeProject);
		if (!saveSuccessful) {
			return false;
		}

		if (!activeProject.saveSessionTools()) {
			return false;
		}

		doSaveProject(activeProject);

		// close the project
		String name = activeProject.getName();
		ProjectLocator projectLocator = activeProject.getProjectLocator();
		activeProject.close();

		// TODO: This should be done by tool.setActiveProject which should always be invoked
		fireProjectClosed(activeProject);

		if (!isExiting) {
			// update the gui now that active project is closed
			tool.setActiveProject(null);
			Msg.info(this, "Closed project: " + name);

			// update the list of project views to include the "active"
			// project that is no longer active
			plugin.rebuildRecentMenus();
			plugin.getProjectManager().setLastOpenedProject(null);
		}
		else {
			plugin.getProjectManager().setLastOpenedProject(projectLocator);
		}

		if (tool.getManagePluginsDialog() != null) {
			tool.getManagePluginsDialog().close();
		}

		return true;
	}

	private void doSaveProject(Project project) {
		project.setSaveableData(DISPLAY_DATA, tool.getSaveableDisplayData());
		project.save();
	}

	private void openProjectAndNotify(Project project) {
		doRestoreProject(project);
		fireProjectOpened(project);
	}

	private void doRestoreProject(Project project) {
		SaveState saveState = project.getSaveableData(DISPLAY_DATA);
		if (saveState == null) {
			return;
		}
		tool.setSaveableDisplayData(saveState);
	}

	private boolean saveChangedData(Project activeProject) {
		List<DomainFile> data = activeProject.getOpenData();
		if (data.isEmpty()) {
			return true;
		}

		DomainObject[] lockedObjects = lockDomainObjects(data);
		if (lockedObjects == null) {
			return false;
		}

		List<DomainFile> changedFiles = getChangedFiles(data);

		try {
			if (!checkReadOnlyFiles(lockedObjects)) {
				return false;
			}

			// pop up dialog to save the data
			SaveDataDialog saveDialog = new SaveDataDialog(tool);
			if (!saveDialog.showDialog(changedFiles)) {
				// user hit the cancel button on the "Save" dialog
				// so cancel closing the project
				return false;
			}
		}
		finally {
			for (DomainObject lockedObject : lockedObjects) {
				lockedObject.unlock();
				lockedObject.release(this);
			}
		}
		return true;
	}

	private List<DomainFile> getChangedFiles(List<DomainFile> data) {
		List<DomainFile> changedFiles = new ArrayList<>();
		for (DomainFile domainFile : data) {
			if (domainFile.isChanged()) {
				changedFiles.add(domainFile);
			}
		}
		return changedFiles;
	}

	/**
	 * Checks the list for read-only files; if any are found, pops up
	 * a dialog for whether to save now or lose changes.
	 * @param objs list of files which correspond to modified 
	 * domain objects.
	 * @return true if there are no read only files OR if the user
	 * wants to lose his changes; false if the user wants to save the
	 * files now, so don't continue.
	 */
	private boolean checkReadOnlyFiles(DomainObject[] objs) {
		ArrayList<DomainObject> list = new ArrayList<>(10);
		for (DomainObject domainObject : objs) {
			try {
				if (domainObject.isChanged() && !domainObject.getDomainFile().canSave()) {
					list.add(domainObject);
				}
			}
			catch (Exception e) {
				Msg.showError(this, null, null, null, e);
			}
		}
		if (list.size() == 0) {
			return true;
		}

		StringBuffer sb = new StringBuffer();
		sb.append("The following files are Read-Only and cannot be\n" +
			" saved 'As Is.' You must do a manual 'Save As' for these\n" + " files: \n \n");

		for (DomainObject obj : list) {
			sb.append(obj.getDomainFile().getPathname());
			sb.append("\n");
		}
		// note: put the extra space in or else OptionDialog will not show
		// the new line char
		sb.append(" \nChoose 'Cancel' to cancel Close Project, or \n");
		sb.append("'Lose Changes' to continue.");

		if (OptionDialog.showOptionDialog(tool.getToolFrame(), "Read-Only Files", sb.toString(),
			"Lose Changes", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
			return true; // Lose changes, so close the project
		}
		return false;
	}

	/**
	 * Fire the project opened event
	 * @param project project being opened
	 */
	private void fireProjectOpened(Project project) {
		for (ProjectListener listener : tool.getListeners()) {
			listener.projectOpened(project);
		}
	}

	/**
	 * Fire the project closed event.
	 * @param project project being closed
	 */
	private void fireProjectClosed(Project project) {
		for (ProjectListener listener : tool.getListeners()) {
			listener.projectClosed(project);
		}
	}

	/**
	 * Action for a recently opened project.
	 *
	 */
	private class ReopenProjectAction extends DockingAction {
		private ProjectLocator projectLocator;

		private ReopenProjectAction(ProjectLocator projectLocator, String filename) {
			super(filename, plugin.getName(), false);
			this.projectLocator = projectLocator;
// ACTIONS - auto generated
			setMenuBarData(new MenuData(
				new String[] { ToolConstants.MENU_FILE, "Reopen", filename }, null, "AProject"));

			tool.setMenuGroup(new String[] { ToolConstants.MENU_FILE, "Reopen" }, "AProject");
			setEnabled(true);
			setHelpLocation(new HelpLocation(plugin.getName(), "Reopen_Project"));
		}

		/* (non Javadoc)
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		@Override
		public void actionPerformed(ActionContext context) {
			doOpenProject(projectLocator);
		}

	}
}
