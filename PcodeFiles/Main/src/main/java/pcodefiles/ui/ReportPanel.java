package pcodefiles.ui;

import javax.swing.*;

public class ReportPanel extends JPanel {
    public ReportPanel() {
        var okFilesLabel = new JLabel("OK Files");
        var badFilesLabel = new JLabel("BAD Files");
        var okPercentageLabel = new JLabel("% ok files");

        var okFilesNr = new JTextField();
        var badFilesNr = new JTextField();
        var okPercentage = new JTextField();

        var nonMatchList = new JList<>(new String[]{});
    }
}
