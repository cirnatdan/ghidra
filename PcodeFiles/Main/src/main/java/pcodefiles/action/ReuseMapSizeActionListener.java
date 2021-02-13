package pcodefiles.action;

import pcodefiles.WinOLSPanel;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class ReuseMapSizeActionListener implements ActionListener {

    private final WinOLSPanel winOLSPanel;
    private final JTextField groupFromText;
    private final JTextField groupToText;
    private final JTextField folderNameText;
    private GenerateJSONActionListener generateJSONActionListener;

    public ReuseMapSizeActionListener(WinOLSPanel winOLSPanel,
                                      JTextField groupFromText,
                                      JTextField groupToText,
                                      JTextField folderNameText,
                                      GenerateJSONActionListener generateJSONActionListener) {
        this.winOLSPanel = winOLSPanel;
        this.groupFromText = groupFromText;
        this.groupToText = groupToText;
        this.folderNameText = folderNameText;
        this.generateJSONActionListener = generateJSONActionListener;
    }
    @Override
    public void actionPerformed(ActionEvent e) {
        File outputDir = winOLSPanel.getSelectedFiles(WinOLSPanel.OUTPUTDIR).get(0);
        var sizeReuseFile = new File(outputDir, "size.reuse");

        if (sizeReuseFile.exists()) {
            sizeReuseFile.delete();
        }
        try {
            sizeReuseFile.createNewFile();
            var writer = new FileWriter(sizeReuseFile);
            writer.write(String.join("::", groupFromText.getText(), groupToText.getText(), folderNameText.getText()));
            writer.write(System.getProperty("line.separator"));

            writer.flush();
            writer.close();
        } catch (IOException ex) {
            ex.printStackTrace();
            return;
        }

        generateJSONActionListener.actionPerformed(e);
    }
}
