package pcodefiles;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import generic.util.Path;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessOptions;
import ghidra.framework.GenericRunInfo;
import ghidra.util.exception.InvalidInputException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class WinOLSAnalyzer {
    public static void runAnalysis(File winOLSScript, List<File> exampleFile, List<File> inputFiles, File outputDir) {
        //find scripts
        ResourceFile ghidraScriptsDir = null;
        if (Path.fromPathString(Path.GHIDRA_HOME + "/../PcodeFiles/Main/ghidra_scripts").exists()) {
            ghidraScriptsDir = Path.fromPathString(Path.GHIDRA_HOME + "/../PcodeFiles/Main/ghidra_scripts");
        } else {
            // we are probably in a jar file
            ghidraScriptsDir = Path.fromPathString(Path.GHIDRA_HOME + "/Main/ghidra_scripts");
        }
        String analyze_possible_offsets = Path.fromPathString(ghidraScriptsDir + "/analyze_possible_offsets.py").getAbsolutePath();
        String parse_winolsscript = Path.fromPathString(ghidraScriptsDir + "/parse_winolsscript.py").getAbsolutePath();
        String find_maps = Path.fromPathString(ghidraScriptsDir +"/find_maps.py").getAbsolutePath();

        HeadlessAnalyzer analyzer = null;
        try {
            analyzer = HeadlessAnalyzer.getInstance();
        } catch (IOException ioException) {
            ioException.printStackTrace();
            return;
        }
        HeadlessOptions options = analyzer.getOptions();
        options.enableAnalysis(true);
        options.enableOverwriteOnConflict(true);
        options.enableReadOnlyProcessing(false);
        options.setPreScripts(new ArrayList<String>() {{ add(analyze_possible_offsets); }});
        options.setPostScriptsWithArgs(
                new ArrayList<Pair<String,String[]>>() {{
                    add( new Pair<>(parse_winolsscript, new String[]{winOLSScript.getAbsolutePath(), outputDir.getAbsolutePath()}));
                }}
        );

        try {
            options.setLoader("BinaryLoader", new LinkedList<>() {{add(new Pair<>("-loader-baseAddr", "0x80000000"));}});
            options.setLanguageAndCompiler("tricore:LE:32:tc176x", null);
        } catch (InvalidInputException invalidInputException) {
            invalidInputException.printStackTrace();
        }

        try {
            analyzer.processLocal(
                    GenericRunInfo.getProjectsDirPath(),
                    winOLSScript.getName(),
                    "",
                    exampleFile);

            options.enableAnalysis(false);
            options.setPreScripts(new ArrayList<String>());
            options.setPostScriptsWithArgs(
                    new ArrayList<Pair<String,String[]>>() {{
                        add( new Pair<>(find_maps, new String[]{outputDir.getAbsolutePath()}));
                    }}
            );

            analyzer.processLocal(
                    GenericRunInfo.getProjectsDirPath(),
                    winOLSScript.getName(),
                    "",
                    inputFiles);
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }
}
