package pcodefiles.ui;

import docking.DialogComponentProvider;
import ghidra.framework.options.SaveState;

import javax.swing.*;

public class ReportDialog extends DialogComponentProvider {
    public ReportDialog(SaveState report) {
        super("Analysis report");

        var reportPanel = new ReportPanel(report);

        var scrollPane = new JScrollPane(reportPanel);
        this.addWorkPanel(scrollPane);
    }
}
