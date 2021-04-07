package pcodefiles.action;

import ghidra.app.services.ConsoleService;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.options.SaveState;
import ghidra.program.model.lang.LanguageService;
import ghidra.util.task.TaskBuilder;
import pcodefiles.AppInfo;
import pcodefiles.WinOLSAnalyzerGUI;
import pcodefiles.WinOLSPanel;
import pcodefiles.WinOLSTool;
import pcodefiles.ui.ReportDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class ProcessFilesActionListener implements ActionListener {

    private final WinOLSTool winOLSTool;
    private ProjectManager projectManager;
    private LanguageService languageService;

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
        List<File> inputFiles = parent.getSelectedFiles(WinOLSPanel.INPUTFILES);
        File outputDir = parent.getSelectedFiles(WinOLSPanel.OUTPUTDIR).get(0);
        boolean reuseAnalysis = parent.reuseAnalysis();

        //@formatter:off
        TaskBuilder.withRunnable(monitor -> {
            monitor.setMaximum(1);
            WinOLSAnalyzerGUI analyzerGUI = null;
            try {
                analyzerGUI = new WinOLSAnalyzerGUI(
                        projectManager,
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
            monitor.setIndeterminate(true);

            monitor.setMessage("Parse winolsscript file");
            var project = analyzerGUI.openProject(winOLSScript);
            project.setSaveableData("analysis_report", new SaveState());
            var report = project.getSaveableData("analysis_report");

            try {
                analyzerGUI.analyzeExampleFirmware(project, winOLSScript, exampleFile, outputDir);
                for (File file: inputFiles) {
                    analyzerGUI.runAnalysis(project, file, outputDir);
                    var scriptcode = report.getString(file.getName() + "_scriptcode", "");
                    if (!"".equals(scriptcode)) {
                        renameFile(file, scriptcode);
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
            winOLSTool.showDialog(dialog);

            })
            .setTitle("Analyze and find maps")
            .setCanCancel(true)
            .setHasProgress(true)
            .launchModal()
        ;
        //@formatter:on
    }

    private void renameFile(File file, String scriptcode) {
        var dirPath = file.toPath().getParent().toString();
        var newName = Paths.get(dirPath, scriptcode);
        if (Files.exists(newName)) {
            var i = 1;
            while(true) {
                if (Files.notExists(Paths.get(dirPath, scriptcode + "(" + i + ")"))) {
                    newName = Paths.get(dirPath, scriptcode + "(" + i + ")");
                    break;
                }
                i++;
            }
        }
        //noinspection ResultOfMethodCallIgnored
        file.renameTo(new File(newName.toString()));
    }
}
