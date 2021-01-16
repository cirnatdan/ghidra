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

import java.awt.Taskbar;
import java.awt.Toolkit;
import java.lang.reflect.Field;

import docking.DockingErrorDisplay;
import docking.DockingWindowManager;
import docking.framework.ApplicationInformationDisplayFactory;
import docking.framework.SplashScreen;
import docking.widgets.PopupKeyStorePasswordProvider;
import ghidra.docking.util.DockingWindowsLookAndFeelUtils;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.PluggableServiceRegistry;
import ghidra.framework.main.GhidraApplicationInformationDisplayFactory;;
import ghidra.framework.preferences.Preferences;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.ErrorDisplay;
import ghidra.util.SystemUtilities;

public class PcodeFilesApplicationConfiguration extends HeadlessGhidraApplicationConfiguration {

    @Override
    public boolean isHeadless() {
        return false;
    }

    @Override
    protected void initializeApplication() {

        DockingWindowsLookAndFeelUtils.loadFromPreferences();

        platformSpecificFixups();

        super.initializeApplication();

        ApplicationKeyManagerFactory.setKeyStorePasswordProvider(
                new PopupKeyStorePasswordProvider());
    }

    private static void platformSpecificFixups() {

        // Set the dock icon for macOS
        if (Taskbar.isTaskbarSupported()) {
            Taskbar taskbar = Taskbar.getTaskbar();
            if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
                taskbar.setIconImage(ApplicationInformationDisplayFactory.getLargestWindowIcon());
            }
        }

        // Set the application title for Linux.
        // This should not be necessary...hopefully in a future version of Java it will just work.
        Class<?> toolkitClass = Toolkit.getDefaultToolkit().getClass();
        if (toolkitClass.getName().equals("sun.awt.X11.XToolkit")) {
            try {
                final Field awtAppClassName = toolkitClass.getDeclaredField("awtAppClassName");
                awtAppClassName.setAccessible(true);
                awtAppClassName.set(null, "Ghidra");
            }
            catch (Exception e) {
                // Not sure what went wrong.  Oh well, we tried.
            }
        }
    }


    @Override
    public void installStaticFactories() {
        super.installStaticFactories();
        PluggableServiceRegistry.registerPluggableService(
                ApplicationInformationDisplayFactory.class,
                new GhidraApplicationInformationDisplayFactory());
    }

    @Override
    public ErrorDisplay getErrorDisplay() {
        return new DockingErrorDisplay();
    }
}

