package pcodefiles.ui;

import docking.DialogComponentProvider;
import ghidra.framework.options.SaveState;

public class ReportDialog extends DialogComponentProvider {
    public ReportDialog(SaveState report) {
        super("Analysis report");

        this.addWorkPanel(new ReportPanel(report));
    }
}
