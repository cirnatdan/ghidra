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
import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.tool.ToolConstants;
import docking.util.AnimationUtils;
import docking.util.image.ToolIconURL;
import generic.util.WindowUtilities;
import ghidra.app.plugin.core.console.ConsolePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;
import ghidra.framework.main.logviewer.model.ChunkModel;
import ghidra.framework.main.logviewer.model.ChunkReader;
import ghidra.framework.main.logviewer.ui.FileViewer;
import ghidra.framework.main.logviewer.ui.FileWatcher;
import ghidra.framework.model.*;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginClassManager;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import org.jdom.Element;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.File;
import java.io.IOException;

/**
 * Tool that serves as the the Ghidra Project Window. Only those plugins that
 * implement the FrontEndable interface may be <i>directly</i> added to this
 * tool by the user. Other plugins that are not marked as FrontEndable may get
 * pulled in because the FrontEndable plugins depend on them. These plugins are
 * aware of what tool they live in so that they can behave in the appropriate
 * manner.
 */
public class WinOLSTool extends PluginTool implements OptionsChangeListener {
	public static final String AUTOMATICALLY_SAVE_TOOLS = "Automatically Save Tools";
	private static final String USE_ALERT_ANIMATION_OPTION_NAME = "Use Notification Animation";

	private static final int MIN_HEIGHT = 600;

	private WeakSet<ProjectListener> listeners;
	private FrontEndPlugin plugin;

	private ComponentProvider compProvider;
	private LogComponentProvider logProvider;

	private WindowListener windowListener;
	private PluginClassManager pluginClassManager;

	/**
	 * Construct a new Ghidra Project Window.
	 *
	 * @param pm project manager
	 */
	public WinOLSTool(ProjectManager pm) {
		super(null, pm, null, null /*tool template*/, false, false, false);
		setToolName("Project Window");

		listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();

		addFrontEndPlugin();
		ensureSize();
		windowListener = new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				getToolFrame().removeWindowListener(windowListener);
			}
		};
		JFrame toolFrame = getToolFrame();
		toolFrame.addWindowListener(windowListener);

		AppInfo.setFrontEndTool(this);
		AppInfo.setActiveProject(getProject());

		createActions();

//		try {
//			this.addPlugin(ConsolePlugin.class.getName());
//		} catch (PluginException e) {
//			e.printStackTrace();
//		}
	}

	private void createActions() {
		DockingAction exitAction = new DockingAction("Exit Ghidra", ToolConstants.TOOL_OWNER) {

			@Override
			public void actionPerformed(ActionContext context) {
				ghidra.framework.main.AppInfo.exitGhidra();
			}
		};

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			// Only install keybinding on non-OSX systems, as OSX handles the Command-Q
			// quit action for us.  If we put the binding on, then we will get the
			// callback twice.
			exitAction.setKeyBindingData(
					new KeyBindingData(KeyEvent.VK_Q, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		}

		exitAction.setEnabled(true);
		addAction(exitAction);
	}

	private void ensureSize() {
		JFrame frame = getToolFrame();
		Dimension size = frame.getSize();
		if (size.height < MIN_HEIGHT) {
			size.height = MIN_HEIGHT;
			Point center = WindowUtilities.centerOnScreen(size);
			frame.setBounds(center.x, center.y, size.width, size.height);
		}
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		if (pluginClassManager == null) {
			pluginClassManager = new PluginClassManager(FrontEndable.class, null);
		}
		return pluginClassManager;
	}

	private void addFrontEndPlugin() {
		plugin = new FrontEndPlugin(this);
		plugin.setProjectManager(getProjectManager());
		try {
			addPlugin(plugin);
		}
		catch (PluginException e) {
			// should not happen
			Msg.showError(this, getToolFrame(), "Can't Create Project Window", e.getMessage(), e);
		}
		compProvider = plugin.getFrontEndProvider();

		showComponentHeader(compProvider, false);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (AUTOMATICALLY_SAVE_TOOLS.equals(optionName)) {
			GhidraTool.autoSave = (Boolean) newValue;
		}
		else if (USE_ALERT_ANIMATION_OPTION_NAME.equals(optionName)) {
			AnimationUtils.setAnimationEnabled((Boolean) newValue);
		}
	}

	@Override
	public void exit() {
		plugin.exitGhidra();
	}

	@Override
	public void close() {
		exit();
	}

	/**
	 * Set the active project.
	 * 
	 * @param project may be null if there is no active project
	 */
	public void setActiveProject(Project project) {

		if (isDisposed) {
			return;
		}

		ToolOptions options = getOptions(ToolConstants.TOOL_OPTIONS);
		options.removeOptionsChangeListener(this);

		setProject(project);
		AppInfo.setActiveProject(project);
		plugin.setActiveProject(project);
	}

	@Override
	public void setVisible(boolean visibility) {
		if (visibility) {
			super.setVisible(visibility);
			plugin.rebuildRecentMenus();
		}
		else {
			super.setVisible(visibility);

			// Treat setVisible(false) as a dispose, as this is the only time we should be hidden
			AppInfo.setFrontEndTool(null);
			AppInfo.setActiveProject(null);
			dispose();
		}
	}

	public void setBusy(boolean busy) {
		JFrame rootFrame = winMgr.getRootFrame();
		Component glassPane = rootFrame.getGlassPane();
		if (!(glassPane instanceof GGlassPane)) {
			Msg.debug(this, "Found root frame without a GhidraGlassPane registered!");
			return;
		}
		GGlassPane dockingGlassPane = (GGlassPane) glassPane;
		dockingGlassPane.setBusy(busy);
	}

	@Override
	public ToolTemplate getToolTemplate(boolean includeConfigState) {
		ToolTemplate toolTemplate = new FrontEndToolTemplate(getIconURL(),
			saveToXml(includeConfigState), getSupportedDataTypes());
		return toolTemplate;
	}

	//////////////////////////////////////////////////////////////////////

	/**
	 * Get project listeners.
	 * 
	 * @return ProjectListener[]
	 */
	Iterable<ProjectListener> getListeners() {
		return listeners;
	}

	// access for Junit tests
	ComponentProvider getProvider() {
		return compProvider;
	}

	SaveState getSaveableDisplayData() {
		SaveState saveState = new SaveState();
		plugin.writeDataState(saveState);
		return saveState;
	}

	void setSaveableDisplayData(SaveState saveState) {
		plugin.readDataState(saveState);
	}

	////////////////////////////////////////////////////////////////////

	@Override
	public boolean canCloseDomainFile(DomainFile df) {
		PluginTool[] tools = getProject().getToolManager().getRunningTools();
		for (PluginTool tool : tools) {
			DomainFile[] files = tool.getDomainFiles();
			for (DomainFile domainFile : files) {
				if (df == domainFile) {
					return tool.canCloseDomainFile(df);
				}
			}
		}
		return true;
	}

	void showGhidraUserLogFile() {
		File logFile = LoggingInitialization.getApplicationLogFile();
		if (logFile == null) {
			return;// something odd is going on; can't find log file
		}

		if (logProvider == null) {
			logProvider = new LogComponentProvider(this, logFile);
			showDialog(logProvider);
			return;
		}

		if (logProvider.isShowing()) {
			logProvider.toFront();
		}
		else {
			showDialog(logProvider, getToolFrame());
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class LogComponentProvider extends DialogComponentProvider {

		private final File logFile;
		private Dimension defaultSize = new Dimension(600, 400);

		private FileWatcher watcher;

		LogComponentProvider(PluginTool tool, File logFile) {
			super("Ghidra User Log", false, false, false, false);

			this.logFile = logFile;

			addWorkPanel(buildWorkPanel());
		}

		/**
		 * Need to override this method so we can stop the file watcher when the
		 * dialog is closed.
		 */
		@Override
		protected void dialogClosed() {
			if (watcher != null) {
				watcher.stop();
			}
		}

		/**
		 * Need to override this method so we can stop the file watcher when the
		 * dialog is closed.
		 */
		@Override
		protected void dialogShown() {
			if (watcher != null) {
				watcher.start();
			}
		}

		private JPanel buildWorkPanel() {

			JPanel panel = new JPanel(new BorderLayout()) {
				@Override
				public Dimension getPreferredSize() {
					return defaultSize;
				}
			};

			try {
				FVEventListener eventListener = new FVEventListener();

				ChunkModel model = new ChunkModel();
				ChunkReader reader = new ChunkReader(logFile, model);
				FileViewer viewer = new FileViewer(reader, model, eventListener);
				panel.add(viewer);
				panel.setVisible(true);

				// Turn on the file watcher so events will be fired off whenever the log file
				// changes.
				watcher = new FileWatcher(logFile, eventListener);
				watcher.start();

				// Now tell subscribers that the file needs to be read-in. Have it view the bottom
				// of the file on startup.
				FVEvent loadEvt = new FVEvent(EventType.SCROLL_END, null);
				eventListener.send(loadEvt);
			}
			catch (IOException e) {
				Msg.error(this, "Exception reading log file", e);
			}

			return panel;
		}
	}

	private static class FrontEndToolTemplate extends GhidraToolTemplate {
		FrontEndToolTemplate(ToolIconURL iconURL, Element element, Class<?>[] supportedDataTypes) {
			super(iconURL, element, supportedDataTypes);
		}
	}

}
