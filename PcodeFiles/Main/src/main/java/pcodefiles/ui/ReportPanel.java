package pcodefiles.ui;

import ghidra.framework.options.SaveState;

import javax.swing.*;
import java.awt.*;

public class ReportPanel extends JPanel {
    public ReportPanel(SaveState report) {
        var okFiles = report.getStrings("okFiles", new String[]{});
        var badFiles = report.getStrings("badFiles", new String[]{});

        var okFilesLabel = new JLabel("OK Files");
        var badFilesLabel = new JLabel("BAD Files");
        var okPercentageLabel = new JLabel("% ok files");

        var okFilesNr = new JTextField();
        okFilesNr.setEditable(false);
        okFilesNr.setText(String.valueOf(okFiles.length));
        var badFilesNr = new JTextField();
        badFilesNr.setEditable(false);
        badFilesNr.setText(String.valueOf(badFiles.length));
        var okPercentage = new JTextField();
        okPercentage.setEditable(false);
        okPercentage.setText(String.valueOf(
                okFiles.length + badFiles.length > 0
                        ? okFiles.length / (okFiles.length + badFiles.length) * 100
                        : 0
                )
        );

        GridBagLayout gbl = new GridBagLayout();
        this.setLayout(gbl);
        int y = 0;

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(okFilesLabel, gbc);
        this.add(okFilesLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(badFilesLabel, gbc);
        this.add(badFilesLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(okPercentageLabel, gbc);
        this.add(okPercentageLabel);

        y++;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(okFilesNr, gbc);
        this.add(okFilesNr);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.gridwidth = 2;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(badFilesNr, gbc);
        this.add(badFilesNr);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(okPercentage, gbc);
        this.add(okPercentage);

        // list

        okFilesLabel = new JLabel("OK Files");
        okFilesLabel.setBackground(Color.green);
        badFilesLabel = new JLabel("BAD Files");
        badFilesLabel.setBackground(Color.red);

        var notFoundLabel = new JLabel("Groups not found");
        var scriptcodeLabel = new JLabel("scriptcode");

        ++y;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(badFilesLabel, gbc);
        this.add(badFilesLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(scriptcodeLabel, gbc);
        this.add(scriptcodeLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(notFoundLabel, gbc);
        this.add(notFoundLabel);

        for (String file: report.getStrings("badFiles", new String[]{})) {
            y++;
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            var fileLabel = new JLabel(file);
            gbl.setConstraints(fileLabel, gbc);
            this.add(fileLabel);

            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            var SW = new JLabel(report.getString(file + "_scriptcode", "NOTFOUND"));
            gbl.setConstraints(SW, gbc);
            this.add(SW);

            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            var groupList = new JList<>(report.getStrings(file, new String[]{}));
            gbl.setConstraints(groupList, gbc);
            this.add(groupList);
        }

        y++;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.insets.top = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(okFilesLabel, gbc);
        this.add(okFilesLabel);

        for (String file: report.getStrings("okFiles", new String[]{})) {
            y++;
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            var fileLabel = new JLabel(file);
            gbl.setConstraints(fileLabel, gbc);
            this.add(fileLabel);

            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            var SW = new JLabel(report.getString(file + "_scriptcode", "NOTFOUND"));
            gbl.setConstraints(SW, gbc);
            this.add(SW);

            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            var groupList = new JList<>(report.getStrings(file, new String[]{}));
            gbl.setConstraints(groupList, gbc);
            this.add(groupList);
        }
    }
}
