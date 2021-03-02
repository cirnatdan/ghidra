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
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.ProgramaticUseOnly;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.NamingUtilities;
import ghidra.util.SystemUtilities;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.net.URL;
import java.util.Collections;
import java.util.Set;

/**
 * Main plugin component for the Ghidra Project Window, which is
 * a PluginTool. This plugin manages all of the GUI elements, e.g., the
 * Data tree panel, view panels for other projects, etc.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidra Core",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Front End",
	description = "Front End Components for Ghidra",
	servicesProvided = { FrontEndService.class }
)
//@formatter:on
public class FrontEndPlugin extends Plugin
		implements FrontEndService, ProgramaticUseOnly {

	private final static String TITLE_PREFIX = "PcodeFiles WinOLS: ";

	private JPanel mainGuiPanel;
	private Project activeProject;
	private ProjectManager projectManager;

	/**
	 * the main scrollable status area used by the DataManager
	 * and ToolManager to provide feedback to the user
	 */
	private LogPanel statusPanel;
	private String projectName;

	private FileActionManager fileActionManager;

	// remove the "." from the project extension
	private static String PROJECT_EXTENSION = ProjectLocator.getProjectExtension().substring(1);

	private FrontEndProvider frontEndProvider;
	private WinOLSPanel winOLSPanel;

	/**
	 * Construct a new FrontEndPlugin. This plugin is constructed once when
	 * the Front end tool (Ghidra Project Window) is created. When a
	 * previously opened project is created, the Ghidra Project Window is
	 * restored to the state associated with that project.
	 * @param tool the front end tool
	 */
	public FrontEndPlugin(PluginTool tool, WinOLSPanel winOLSPanel) {
		super(tool);
		this.winOLSPanel = winOLSPanel;

		SystemUtilities.assertTrue(tool instanceof WinOLSTool,
			"FrontEndPlugin requires a FrontEndTool");
		frontEndProvider = new FrontEndProvider(tool);
		tool.addComponentProvider(frontEndProvider, true);
		tool.setDefaultComponent(frontEndProvider);

		buildGui();

		fileActionManager = new FileActionManager(this);
		setProjectName();
	}

	FrontEndProvider getFrontEndProvider() {
		return frontEndProvider;
	}

	WinOLSTool getFrontEndTool() {
		return (WinOLSTool) tool;
	}

	public JComponent getComponent() {
		return mainGuiPanel;
	}

	/**
	 * Set the project manager; try to reopen the last project that was
	 * opened.
	 * @param pm the project manager
	 */
	void setProjectManager(ProjectManager pm) {
		this.projectManager = pm;
	}

	/**
	 * Sets the handle to the activeProject, as well as updating the
	 * active data tree to show the new active project's data
	 * @param project the active project
	 */
	void setActiveProject(Project project) {

		// set the active project handle to the specified "new" project
		activeProject = project;

		// update the rest of the panels with new (or inactive) project
		if (project != null) {
			GenericRunInfo.setProjectsDirPath(project.getProjectLocator().getLocation());
		}

		// update the title bar and other panel's border titles
		setProjectName();

//        gui.validate();
	}

	/**
	 * sets the name of the project, using the default name if no project is active
	 */
	void setProjectName() {
		projectName =
			(activeProject == null ? ToolConstants.NO_ACTIVE_PROJECT : activeProject.getName());
		String title = TITLE_PREFIX + projectName;

		tool.setToolName(title);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		//projectDataPanel.writeDataState(saveState);
	}

	@Override
	public void readDataState(SaveState saveState) {
		//projectDataPanel.readDataState(saveState);
	}

	/**
	 * Exit the Ghidra application; the parameter indicates whether
	 * the user should be prompted to save the project that is about
	 * to be closed
	 */
	void exitGhidra() {
		boolean okToExit = closeActiveProject();
		if (okToExit) {
			System.exit(0);

		}
		else if (!tool.isVisible()) {
			tool.setVisible(true);
		}
	}

	private boolean closeActiveProject() {
		if (activeProject == null) {
			return true;
		}
		try {
			return fileActionManager.closeProject(true);
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e); // Keep this.
			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), "Close Project Failed",
				"Error Description: [ " + e + " ]" + "\n" +
					"=====> Do you wish to exit Ghidra, possibly losing changes? <=====",
				"Exit Ghidra (Possibly Lose Changes)", OptionDialog.ERROR_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
		}
		return true;
	}

	/**
	 * general project utility that brings up a file chooser for
	 * the user to specify a directory and filename that are used
	 * for the Project location and name
	 * 
	 * @param fileChooser the chooser used to pick the project
	 * @param mode read-only or not
	 * @param preferenceName the preference property name used to save the last opened project
	 * @return the project locator for the opened project 
	 */
	ProjectLocator chooseProject(GhidraFileChooser fileChooser, String mode,
			String preferenceName) {
		boolean create = (mode.equals("Create")) ? true : false;
		fileChooser.setTitle(mode + " a Ghidra Project");
		fileChooser.setApproveButtonText(mode + " Project");
		fileChooser.setApproveButtonToolTipText(mode + " a Ghidra Project");
		fileChooser.setSelectedFile(null);

		boolean validInput = false;
		while (!validInput) {
			File file = fileChooser.getSelectedFile();

			if (file != null) {
				String path = file.getAbsoluteFile().getParent();
				String filename = file.getName();

				// strip off extension since the LocalRootFolder takes care of it
				if (filename.endsWith(PROJECT_EXTENSION)) {
					filename = filename.substring(0, filename.lastIndexOf(PROJECT_EXTENSION) - 1);
				}
				// if user enters the name of the project manually and leaves off
				// the extension, try to open or create using the extension
				else if (!create && filename.lastIndexOf(".") > path.lastIndexOf(File.separator)) {
					// treat opening a file without the ghidra extension as an error
					Msg.showError(getClass(), tool.getToolFrame(), "Invalid Project File",
						"Cannot open '" + file.getName() + "' as a Ghidra Project");
					continue;
				}
				if (!NamingUtilities.isValidProjectName(filename)) {
					Msg.showError(getClass(), tool.getToolFrame(), "Invalid Project Name",
						filename + " is not a valid project name");
					continue;
				}
				Preferences.setProperty(preferenceName, path);
				try {
					Preferences.store();
				}
				catch (Exception e) {
					Msg.debug(this,
						"Unexpected exception storing preferences to" + Preferences.getFilename(),
						e);
				}
				return new ProjectLocator(path, filename);
			}
			return null;
		}

		return null;
	}

	boolean confirmDelete(String message) {
		int option = OptionDialog.showOptionDialogWithCancelAsDefaultButton(tool.getToolFrame(),
			"Confirm Delete", "Are you sure you want to delete\n" + message, "Delete",
			OptionDialog.QUESTION_MESSAGE);

		return (option != OptionDialog.CANCEL_OPTION);
	}

	void selectFiles(final Set<DomainFile> files) {
		// Do this later in case any of the given files are newly created, which means that the
		// GUIs may have not yet been notified.
		SwingUtilities.invokeLater(() -> {
			// there was a delete bug; make the set unmodifiable to catch this earlier
			Set<DomainFile> unmodifiableFiles = Collections.unmodifiableSet(files);
		});
	}

	final Project getActiveProject() {
		return activeProject;
	}

	final ProjectManager getProjectManager() {
		return projectManager;
	}

	void rebuildRecentMenus() {

	}

	GhidraFileChooser createFileChooser(String preferenceName) {
		// start the browsing in the user's preferred project directory
		File projectDir = new File(GenericRunInfo.getProjectsDirPath());
		if (preferenceName != null) {
			String dirPath = Preferences.getProperty(preferenceName, null, true);
			if (dirPath != null) {
				projectDir = new File(dirPath);
			}
		}

		GhidraFileChooser fileChooser = new GhidraFileChooser(tool.getToolFrame());
		fileChooser.setCurrentDirectory(projectDir);
		fileChooser.setMultiSelectionEnabled(false);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		fileChooser.setFileFilter(new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "Ghidra Projects (*" + ProjectLocator.getProjectExtension() + ")";
			}

			@Override
			public boolean accept(File pathname, GhidraFileChooserModel model) {
				String lowerCaseName = pathname.getName().toLowerCase();
				if (model.isDirectory(pathname)) {
					return !lowerCaseName.endsWith(ProjectLocator.getProjectDirExtension());
				}
				if (lowerCaseName.endsWith(ProjectLocator.getProjectExtension())) {
					return true;
				}
				return false;
			}
		});
		fileChooser.rescanCurrentDirectory();
		return fileChooser;
	}

	/**
	 * builds the gui for the new front end
	 */
	private void buildGui() {

		// create the major GUI components for the user interface

		// build the panels used in the front end GUI
		buildPanels();
	}

	@Override
	protected void dispose() {
	}

	private void buildPanels() {

		// build the status panel since some of the other panels update status
		// when there is an active project at start up
		statusPanel = new LogPanel(this);
		statusPanel.setHelpLocation(new HelpLocation("FrontEndPlugin", "StatusWindow"));

		// construct the main panel to contain the toolbar and
		// data tree panels (active and read-only views)
		JPanel mainPanel = new JPanel(new BorderLayout());
		//mainPanel.add(toolBar, BorderLayout.NORTH);
		mainPanel.add(winOLSPanel, BorderLayout.CENTER);


		JPanel bottomPane = new JPanel();
		bottomPane.setLayout(new BoxLayout(bottomPane, BoxLayout.Y_AXIS));
		bottomPane.add(Box.createVerticalGlue());
		bottomPane.add(Box.createVerticalStrut(2));

		bottomPane.add(statusPanel);
		bottomPane.add(Box.createVerticalGlue());

		mainGuiPanel = new JPanel(new BorderLayout(5, 5));
		mainGuiPanel.add(mainPanel, BorderLayout.CENTER);
		mainGuiPanel.add(bottomPane, BorderLayout.SOUTH);
	}

	@Override
	public void addProjectListener(ProjectListener l) {
		((FrontEndTool) tool).addProjectListener(l);
	}

	@Override
	public void removeProjectListener(ProjectListener l) {
		if (tool != null) { // tool is null when we've been disposed
			((FrontEndTool) tool).removeProjectListener(l);
		}
	}

	class FrontEndProvider extends ComponentProvider {
		public FrontEndProvider(PluginTool tool) {
			super(tool, "FrontEnd", "FrontEnd Tool");
			setTitle("Project Window");
			setDefaultWindowPosition(WindowPosition.TOP);
		}

		@Override
		public JComponent getComponent() {
			return FrontEndPlugin.this.getComponent();
		}

//		@Override
//		public ActionContext getActionContext(MouseEvent e) {
//			return FrontEndPlugin.this.getActionContext(this, e);
//		}

		@Override
		public HelpLocation getHelpLocation() {
			return new HelpLocation(FrontEndPlugin.this.getName(), "Project_Window");
		}
	}
}
