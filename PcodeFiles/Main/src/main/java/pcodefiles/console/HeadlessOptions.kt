package pcodefiles.console

import java.io.File

class HeadlessOptions {
    var winOLSScript: File? = null;
    var exampleFile: File? = null;
    val inputFiles: MutableList<File> = mutableListOf();
    var outputDir: File? = null;
}