package pcodefiles;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import generic.util.Path;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.store.LockException;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class WinOLSAnalyzerGUI {
    private ProjectManager projectManager;

    public WinOLSAnalyzerGUI(ProjectManager projectManager) {
        this.projectManager = projectManager;
    }

    public void runAnalysis(File winOLSScript, List<File> exampleFile, List<File> inputFiles, File outputDir, boolean reuseAnalysis) {
        var consoleService = AppInfo.getFrontEndTool().getService(ConsoleService.class);
        consoleService.println("Start analysis for " + winOLSScript.getAbsolutePath());

        var projectLocator = new ProjectLocator(GenericRunInfo.getProjectsDirPath(), winOLSScript.getName());

        if (AppInfo.getActiveProject() != null) {
            AppInfo.getActiveProject().close();
        }

        if (!reuseAnalysis) {
            if (projectManager.projectExists(projectLocator)) {
                projectManager.deleteProject(projectLocator);
            }
        }

        Project project = null;
        if (!projectManager.projectExists(projectLocator)) {
            try {
                project = projectManager.createProject(projectLocator, null, true);
            } catch (IOException e) {
                Msg.error(this, "Project creation Exception: " + e.getMessage(), e);
                return;
            }
        } else {
            try {
                project = projectManager.openProject(projectLocator, true, true);
            } catch (NotFoundException | NotOwnerException | LockException e) {
                Msg.error(this, "Project open Exception: " + e.getMessage(), e);
                return;
            }
        }
        AppInfo.getFrontEndTool().setActiveProject(project);
        try {
            var language =
                    DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("tricore:LE:32:tc176x"));
            Program exampleProgram;
            var rootFolder = project.getProjectData().getRootFolder();
            if (reuseAnalysis && null != rootFolder.getFile(exampleFile.get(0).getName())) {
                exampleProgram = (Program) rootFolder.getFile(exampleFile.get(0).getName()).getDomainObject(
                        this, true, false, TaskMonitor.DUMMY);
            } else {
                exampleProgram = AutoImporter.importByUsingSpecificLoaderClassAndLcs(exampleFile.get(0),
                        project.getProjectData().getRootFolder(),
                        BinaryLoader.class,
                        new LinkedList<>() {{
                            add(new Pair<>("-loader-baseAddr", "0x80000000"));
                        }},
                        language,
                        language.getDefaultCompilerSpec(),
                        this,
                        new MessageLog(),
                        TaskMonitor.DUMMY);
                runScript("analyze_possible_offsets.py", new String[]{}, consoleService, exampleProgram);
                if (exampleProgram.canSave())
                    exampleProgram.save("analyzed_possible_offsets", TaskMonitor.DUMMY);
            }

            assert exampleProgram != null;
            var transactionId = exampleProgram.startTransaction("analysis");
            var analysisOptions = exampleProgram.getOptions(Program.ANALYSIS_PROPERTIES);
            var analysisMgr = AutoAnalysisManager.getAnalysisManager(exampleProgram);
            analysisOptions.setBoolean("DWARF", false);
            analysisOptions.setBoolean("ARM Symbol", false);
            analysisOptions.setBoolean("Embedded Media", false);
            analysisMgr.initializeOptions();
            if (!reuseAnalysis)
                analysisMgr.reAnalyzeAll(null);
            analysisMgr.startAnalysis(TaskMonitor.DUMMY, true);
            exampleProgram.endTransaction(transactionId, true);
            if (exampleProgram.canSave())
                exampleProgram.save("analysis", TaskMonitor.DUMMY);
            runScript("parse_winolsscript.py", new String[]{winOLSScript.getAbsolutePath(), outputDir.getAbsolutePath()}, consoleService, exampleProgram);

            for (File file: inputFiles) {
                var program = AutoImporter.importByUsingSpecificLoaderClassAndLcs(file,
                        null,
                        BinaryLoader.class,
                        new LinkedList<>() {{
                            add(new Pair<>("-loader-baseAddr", "0x80000000"));
                        }},
                        language,
                        language.getDefaultCompilerSpec(),
                        this,
                        new MessageLog(),
                        TaskMonitor.DUMMY);
                if (program == null) {
                    Msg.error(this, "Program " + file.getName() + " could not be imported");
                } else {
                    consoleService.println("Looking for maps in " + file.getName());
                    program.setTemporary(true);
                    runScript("find_maps.py", new String[]{outputDir.getAbsolutePath()}, consoleService, program);
                }
            }

        } catch (NotFoundException | NotOwnerException | LockException e) {
            Msg.error(this, "Project open Exception: " + e.getMessage(), e);
            return;
        } catch (IOException | InvalidNameException | CancelledException | VersionException | DuplicateNameException e) {
            Msg.error(this, "Program import Exception: " + e.getMessage(), e);
            return;
        } catch (IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            Msg.error(this, "Script run Exception: " + e.getMessage(), e);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void runScript(String scriptName, String[] args, ConsoleService consoleService, Program exampleProgram) throws Exception {
        Msg.info(this,"Running script " + scriptName);
        var scriptFile = new ResourceFile(
                Path.fromPathString(Path.GHIDRA_HOME + "/../PcodeFiles/Main/ghidra_scripts/" + scriptName).getFile(false)
        );
        var script = Objects.requireNonNull(GhidraScriptUtil.getProvider(scriptFile)).getScriptInstance(scriptFile, consoleService.getStdOut());
        script.setScriptArgs(args);
        script.execute(
                new GhidraState(AppInfo.getFrontEndTool(), AppInfo.getActiveProject(), exampleProgram, null, null, null),
                TaskMonitor.DUMMY,
                consoleService.getStdOut()
        );
    }
}
