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
import ghidra.GhidraJarApplicationLayout;

public class JarRun {

	public static void main(String[] args) throws Exception {
		GhidraApplicationLayout layout = new GhidraJarApplicationLayout();
		new PcodeFilesRun().launch(layout, removeArgs(args, 1));
	}

	private static String[] removeArgs(String[] args, int removalCount) {
		String[] newArgs = new String[Math.max(0, args.length - removalCount)];
		if (newArgs.length != 0) {
			System.arraycopy(args, removalCount, newArgs, 0, newArgs.length);
		}
		return newArgs;
	}

	private static void usage() {
		System.out.println("Ghidra GUI Usage:  java -jar <ghidra.jar> -gui [<ghidra-project-file>]");
		System.exit(1);
	}

}
