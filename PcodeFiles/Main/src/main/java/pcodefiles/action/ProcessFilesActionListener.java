package pcodefiles.action;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ghidra.app.services.ConsoleService;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.options.SaveState;
import ghidra.program.model.lang.LanguageService;
import ghidra.util.task.TaskBuilder;
import pcodefiles.AppInfo;
import pcodefiles.WinOLSProjectManager;
import pcodefiles.analysis.UtilsHelper;
import pcodefiles.analysis.WinOLSAnalyzer;
import pcodefiles.model.Group;
import pcodefiles.ui.PatternsWindow;
import pcodefiles.ui.WinOLSPanel;
import pcodefiles.WinOLSTool;
import pcodefiles.model.Report;
import pcodefiles.ui.ReportDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class ProcessFilesActionListener implements ActionListener {

    private final WinOLSTool winOLSTool;
    private final ProjectManager projectManager;
    private final LanguageService languageService;

    public ProcessFilesActionListener(WinOLSTool winOLSTool,
                                      ProjectManager projectManager,
                                      LanguageService languageService) {
        this.winOLSTool = winOLSTool;
        this.projectManager = projectManager;
        this.languageService = languageService;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        JButton button = (JButton) e.getSource();
        WinOLSPanel parent = (WinOLSPanel) button.getParent();

        File winOLSScript = parent.getSelectedFiles(WinOLSPanel.WINOLSSCRIPT).get(0);
        List<File> exampleFile = parent.getSelectedFiles(WinOLSPanel.EXAMPLEFILE);
        List<File> inputFiles = "patterns".equals(button.getName()) ? null : parent.getSelectedFiles(WinOLSPanel.INPUTFILES);
        File outputDir = "patterns".equals(button.getName()) ? null : parent.getSelectedFiles(WinOLSPanel.OUTPUTDIR).get(0);
        boolean reuseAnalysis = parent.reuseAnalysis();

        //@formatter:off
        TaskBuilder.withRunnable(monitor -> {
            monitor.setMaximum(1);
            WinOLSAnalyzer analyzerGUI;
            try {
                analyzerGUI = new WinOLSAnalyzer(
                        winOLSTool.getService(ConsoleService.class),
                        monitor,
                        reuseAnalysis,
                        languageService
                );
                monitor.incrementProgress(1);
            } catch (Exception ex) {
                ex.printStackTrace();
                monitor.cancel();
                return;
            }
            var winOLSPM = new WinOLSProjectManager(
                    projectManager,
                    winOLSTool.getService(ConsoleService.class),
                    reuseAnalysis
            );
            monitor.setIndeterminate(true);

            monitor.setMessage("Parse winolsscript file");
            var project = winOLSPM.openProject(winOLSScript);
            AppInfo.getFrontEndTool().setActiveProject(project);
            assert project != null;
            project.setSaveableData("analysis_report", new SaveState());
            var report = project.getSaveableData("analysis_report");

            try {
                analyzerGUI.analyzeExampleFirmware(project, winOLSScript, exampleFile.get(0), outputDir);
                if (button.getName().equals("patterns")) {
                    var parseResult = project.getSaveableData("winOLSParseResult");
                    var patterns = new HashMap<String,List<String>>();

                    var gson = new Gson();
                    var groups = gson.fromJson(
                            parseResult.getString("winOLS_groups", "[]"),
                            new TypeToken<List<Map<String,Object>>>(){}.getType()
                    );
                    for (Map<String,Object> g: (List<Map<String,Object>>)groups) {
                        var group = Group.fromMap(g);
                        patterns.put(group.getId() + " " + group.getName(),
                                Arrays.asList(parseResult.getStrings(group.getId() + "_patterns", new String[0])));
                    }

                    new PatternsWindow(patterns);

                    return;
                }
                for (File file: inputFiles) {
                    analyzerGUI.runAnalysis(project, file, outputDir);
                    var scriptcode = report.getString(file.getName() + "_scriptcode", "");
                    if (!"".equals(scriptcode)) {
                        analyzerGUI.renameFile(file, scriptcode);
                    }
                }

            } catch (Exception exception) {
                exception.printStackTrace();
                monitor.cancel();
                return;
            }

            var dialog = new ReportDialog(
                    report
            );
            saveReport(outputDir, new Report(report));
            winOLSTool.showDialog(dialog);

            })
            .setTitle("Analyze and find maps")
            .setCanCancel(true)
            .setHasProgress(true)
            .launchModal()
        ;
        //@formatter:on
    }

    private void saveReport(File outputDir, Report report) {
        OutputStream os;
        try {
            os = new FileOutputStream(new File(outputDir, "analysis_report.txt"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        }
        String encoding = "UTF8";
        OutputStreamWriter osw;
        try {
            osw = new OutputStreamWriter(os, encoding);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return;
        }
        BufferedWriter bw = new BufferedWriter(osw);

        try {
            bw.write("# SUMMARY \n");
            bw.write("OK Files \t Bad Files \t % OK Files \n");
            bw.write(report.getOkFiles().length
                    + " \t\t " + report.getBadFiles().length
                    + " \t\t " + report.getOkPercentage()
                    + " \n"
            );

            bw.write("\n\n");
            bw.write("# Bad Files \n");
            bw.write("File \t scriptcode \t Groups not found \n");
            for (String file : report.getBadFiles()) {
                bw.write(file
                    + " \t " + report.getScriptCode(file)
                    + " \t " + String.join(",", Objects.requireNonNull(report.getNotFoundGroups(file)))
                    + " \n");
            }

            bw.write("\n\n");
            bw.write("# OK Files \n");
            bw.write("File \t scriptcode \n");
            for (String file : report.getOkFiles()) {
                bw.write(file
                        + " \t " + report.getScriptCode(file)
                        + " \n");
            }

            bw.flush();
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
