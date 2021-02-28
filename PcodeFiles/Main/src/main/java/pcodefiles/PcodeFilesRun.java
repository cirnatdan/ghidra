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

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.GhidraThreadGroup;
import ghidra.framework.Application;
import ghidra.framework.remote.InetNameLookup;
import ghidra.util.SystemUtilities;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Main Ghidra application class. Creates
 * the .ghidra folder that contains the user preferences and tools if it does
 * not exist. Initializes JavaHelp and attempts to restore the last opened
 * project.
 * <p> A list of classes for plugins, data types, and language providers is
 * maintained so that a search of the classpath is not done every time
 * Ghidra is run. The list is maintained in the GhidraClasses.xml file
 * in the user's .ghidra folder. A search of the classpath is done if the
 * (1) GhidraClasses.xml file is not found, (2) the classpath is different
 * from when the last time Ghidra was run, (3) a class in the file was
 * not found,  or (4) a modification date specified in the classes file for
 * a jar file is older than the actual jar file's modification date.
 *
 * <p><strong>Note</strong>: The Plugin path is a user preference that
 * indicates locations for where classes for plugins and data types should
 * be searched; the Plugin path can include jar files just like a classpath.
 * The Plugin path can be changed by using the <i>Edit Plugin Path</i> dialog,
 * displayed from the <i>Edit-&gt;Edit Plugin Path...</i> menu option on the main
 * Ghidra project window.
 *
 * @see ghidra.GhidraLauncher
 */
public class PcodeFilesRun implements GhidraLaunchable {

    private Logger log; // intentionally load later, after initialization

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) {

        Runnable mainTask = () -> {
            var injector = new Injector();
            Application.initializeApplication(layout, injector.getApplicationConfiguration());

            log = LogManager.getLogger(PcodeFilesRun.class);
            log.info("User " + SystemUtilities.getUserName() + " started Ghidra.");

            var mainHelper = injector.getMainHelper();
            mainHelper.run(args);
        };

        // Automatically disable reverse name lookup if failure occurs
        InetNameLookup.setDisableOnFailure(true);

        // Start main thread in GhidraThreadGroup
        Thread mainThread = new Thread(new GhidraThreadGroup(), mainTask, "Ghidra");
        mainThread.start();
    }
}

