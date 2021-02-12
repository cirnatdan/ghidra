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
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
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
    private final ConsoleService consoleService;
    private final Language language;
    private TaskMonitor monitor;
    private boolean reuseAnalysis;
    private ProjectManager projectManager;

    public WinOLSAnalyzerGUI(ProjectManager projectManager, ConsoleService consoleService, TaskMonitor monitor, boolean reuseAnalysis) throws LanguageNotFoundException {
        this.projectManager = projectManager;
        this.consoleService = consoleService;
        this.monitor = monitor;
        this.reuseAnalysis = reuseAnalysis;

        this.language =
                DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("tricore:LE:32:tc176x"));
    }

    public Project openProject(File winOLSScript) {
        consoleService.println("Opening project " + winOLSScript.getAbsolutePath());
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
                return null;
            }
        } else {
            try {
                project = projectManager.openProject(projectLocator, true, true);
            } catch (NotFoundException | NotOwnerException | LockException e) {
                Msg.error(this, "Project open Exception: " + e.getMessage(), e);
                return null;
            }
        }
        AppInfo.getFrontEndTool().setActiveProject(project);
        return project;
    }

    public Program analyzeExampleFirmware(Project project, File winOLSScript, List<File> exampleFile, File outputDir) throws Exception {
        consoleService.println("Start analysis for " + winOLSScript.getAbsolutePath());

        Program exampleProgram;
        var rootFolder = project.getProjectData().getRootFolder();
        if (reuseAnalysis && null != rootFolder.getFile(exampleFile.get(0).getName())) {
            exampleProgram = (Program) rootFolder.getFile(exampleFile.get(0).getName()).getDomainObject(
                    this, true, false, monitor);
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
                    monitor);
            monitor.setMessage("Scanning for  possible offsets");
            runScript("analyze_possible_offsets.py", new String[]{}, consoleService, exampleProgram);
            if (exampleProgram.canSave())
                exampleProgram.save("analyzed_possible_offsets", monitor);
        }

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
            exampleProgram.save("analysis", monitor);
        monitor.setMessage("Parsing winolsskript");
        runScript("parse_winolsscript.py", new String[]{winOLSScript.getAbsolutePath(), outputDir.getAbsolutePath()}, consoleService, exampleProgram);

        return exampleProgram;
    }

    public void runAnalysis(File winOLSScript, Program exampleProgram, List<File> inputFiles, File outputDir, Project project) {
        try {
            for (File file: inputFiles) {
                monitor.setMessage("Analyzing " + file.getName());
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
                        monitor);
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
                monitor,
                consoleService.getStdOut()
        );
    }
}
