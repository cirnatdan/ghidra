package pcodefiles.action;

import ghidra.util.task.TaskBuilder;
import pcodefiles.WinOLSAnalyzerGUI;
import pcodefiles.WinOLSAnalyzerHeadless;
import pcodefiles.WinOLSPanel;
import pcodefiles.WinOLSTool;

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

        var analyzerGUI = new WinOLSAnalyzerGUI(winOLSTool.getProjectManager());

        //@formatter:off
        TaskBuilder.withRunnable(monitor -> {
            analyzerGUI.runAnalysis(winOLSScript, exampleFile, inputFiles, outputDir, reuseAnalysis);
            })
            .setTitle("Analyze and find maps")
            .setCanCancel(false)
            .setHasProgress(false)
            .launchModal()
        ;
        //@formatter:on

        //WinOLSAnalyzerHeadless.runAnalysis(winOLSScript, exampleFile, inputFiles, outputDir, reuseAnalysis);
    }
}
