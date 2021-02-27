package pcodefiles.action;

import ghidra.app.services.ConsoleService;
import ghidra.framework.options.SaveState;
import ghidra.util.Msg;
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

    public ProcessFilesActionListener(WinOLSTool winOLSTool) {
        this.winOLSTool = winOLSTool;
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
                        winOLSTool.getProjectManager(),
                        AppInfo.getFrontEndTool().getService(ConsoleService.class),
                        monitor,
                        reuseAnalysis
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
            try {
                analyzerGUI.analyzeExampleFirmware(project, winOLSScript, exampleFile, outputDir);
                project.setSaveableData("analysis_report", new SaveState());
                analyzerGUI.runAnalysis(project, inputFiles, outputDir);
            } catch (Exception exception) {
                exception.printStackTrace();
                monitor.cancel();
                return;
            }

            var report = project.getSaveableData("analysis_report");

            for (File file: inputFiles) {
                var scriptcode = report.getString(file.getName() + "_scriptcode", "");
                if (!"".equals(scriptcode)) {
                    renameFile(file, scriptcode);
                }
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
        file.renameTo(new File(newName.toString()));
    }
}
