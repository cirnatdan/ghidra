package pcodefiles.action;

import docking.DockingWindowManager;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskBuilder;
import pcodefiles.*;
import pcodefiles.ui.SizeReuseDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.List;

public class GenerateJSONActionListener implements ActionListener {

    private WinOLSTool winOLSTool;

    public GenerateJSONActionListener(WinOLSTool winOLSTool) {
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
            } catch (LanguageNotFoundException languageNotFoundException) {
                languageNotFoundException.printStackTrace();
                monitor.cancel();
                return;
            }
            monitor.setIndeterminate(true);

            monitor.setMessage("Parse winolsscript file");
            var project = analyzerGUI.openProject(winOLSScript);
            try {
                var program = analyzerGUI.analyzeExampleFirmware(project, winOLSScript, exampleFile, outputDir);
                SystemUtilities.runSwingNow(() ->
                        DockingWindowManager.showDialog(new SizeReuseDialog(
                            new File(outputDir.getAbsolutePath(), "code.patterns"),
                            new File(outputDir.getAbsolutePath(), "size.reuse")
                        ))
                );

                analyzerGUI.runAnalysis(winOLSScript, program, inputFiles, outputDir, project);
            } catch (Exception exception) {
                exception.printStackTrace();
                monitor.cancel();
            }

            })
            .setTitle("Analyze and find maps")
            .setCanCancel(true)
            .setHasProgress(true)
            .launchModal()
        ;
        //@formatter:on

        //WinOLSAnalyzerHeadless.runAnalysis(winOLSScript, exampleFile, inputFiles, outputDir, reuseAnalysis);
    }
}
