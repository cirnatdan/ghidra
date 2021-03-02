package pcodefiles;

import docking.options.editor.ButtonPanelFactory;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GDLabel;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import org.apache.commons.io.FilenameUtils;
import pcodefiles.action.ProcessFilesActionListener;
import pcodefiles.action.ReuseMapSizeActionListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WinOLSPanel extends JPanel {
    public static final String WINOLSSCRIPT = "WINOLSSCRIPT";
    public static final String EXAMPLEFILE = "EXAMPLEFILE";
    public static final String INPUTFILES = "INPUTFILES";
    public static final String OUTPUTDIR = "OUTPUTDIR";

    private final JButton winOLSBrowseButton;
    private JTextField winolsScriptField;
    private Map<String,GhidraFileChooser> fileChoosers = new HashMap<String,GhidraFileChooser>();
    private Map<String,List<File>> selectedFiles = new HashMap<>();
    private boolean reuseAnalysis;

    public WinOLSPanel(ProcessFilesActionListener processFilesActionListener) {
        super();
        reuseAnalysis = false;

        setBorder(BorderFactory.createTitledBorder("Process .winolsscript"));

        JComboBox<String> selectECUField = new JComboBox<>(
                new DefaultComboBoxModel<>(new String[]{"BMW EDC17C50"})

        );

        JLabel winOLSFileLabel = new GDLabel("WinOLS script:", SwingConstants.RIGHT);
        winolsScriptField = new JTextField(25);
        winolsScriptField.setName(WINOLSSCRIPT);

        String lastDirSelected = Preferences.getProperty(WinOLSPreferences.LAST_WINOLS_SCRIPT_DIRECTORY);
//        if (lastDirSelected != null) {
//            winolsScriptField.setText(lastDirSelected);
//            winolsScriptField.setCaretPosition(winolsScriptField.getText().length() - 1);
//        }

        var sizeFromLabel = new JLabel("Use size from ");
        var groupFromText = new JTextField("KF", 5);
        var sizeToLabel = new JLabel("-");
        var groupToText = new JTextField("KF", 5);
        var folderNameLabel = new JLabel("for folder ");
        var folderNameText = new JTextField(8);

        winOLSBrowseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
        winOLSBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                displayFileChooser(
                        winolsScriptField,
                        "Select a WinOLS script file",
                        "Select a WinOLS script file",
                        "Select a WinOLS script file",
                        GhidraFileChooserMode.FILES_ONLY,
                        false
                );
            }
        });

        JLabel exampleFirmwareFileLabel = new GDLabel("Example .bin file :", SwingConstants.RIGHT);
        JTextField exampleFirmwareFileField = new JTextField(25);
        exampleFirmwareFileField.setName(EXAMPLEFILE);

        JButton exampleFileBrowseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
        exampleFileBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                displayFileChooser(
                        exampleFirmwareFileField,
                        "Select the example firmware file",
                        "Select firmware file (.bin)",
                        "Select firmware file (.bin)",
                        GhidraFileChooserMode.FILES_ONLY,
                        false
                );
            }
        });

        JCheckBox reuseAnalysisCheckbox = new JCheckBox("Reuse firmware and winolsscript analysis (saves time)");
        reuseAnalysisCheckbox.setSelected(reuseAnalysis);
        reuseAnalysisCheckbox.addItemListener(e -> {
            if (ItemEvent.SELECTED == e.getStateChange()) {
                reuseAnalysis = true;
            } else if (ItemEvent.DESELECTED == e.getStateChange()) {
                reuseAnalysis = false;
            }
        });

        JLabel inputFilesLabel = new GDLabel("Input files :", SwingConstants.RIGHT);
        JTextField inputFilesField =  new JTextField(25);
        inputFilesField.setName(INPUTFILES);

        JButton inputFilesBrowseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
        inputFilesBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                displayFileChooser(
                        inputFilesField,
                        "Select input files for processing",
                        "Select input files (.bin)",
                        "Select firmware input files",
                        GhidraFileChooserMode.FILES_AND_DIRECTORIES,
                        true
                );
            }
        });

        JLabel outputFilesLabel = new GDLabel("Output JSON directory :", SwingConstants.RIGHT);
        JTextField outputFilesField =  new JTextField(25);
        outputFilesField.setName(OUTPUTDIR);

        JButton outputFilesBrowseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
        outputFilesBrowseButton.addActionListener(e -> displayFileChooser(
                outputFilesField,
                "Select output directory for JSON files",
                "Select output directory",
                "Select output directory for JSON files",
                GhidraFileChooserMode.DIRECTORIES_ONLY,
                false
        ));

        JButton processButton = ButtonPanelFactory.createButton("Process files");

        processButton.addActionListener(
                new ReuseMapSizeActionListener(
                        this,
                        groupFromText,
                        groupToText,
                        folderNameText,
                        processFilesActionListener
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
        gbl.setConstraints(selectECUField, gbc);
        this.add(selectECUField);

        var reuseSizePanel = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(reuseSizePanel, gbc);
        this.add(reuseSizePanel);
        reuseSizePanel.add(sizeFromLabel);
        reuseSizePanel.add(groupFromText);
        reuseSizePanel.add(sizeToLabel);
        reuseSizePanel.add(groupToText);
        reuseSizePanel.add(folderNameLabel);
        reuseSizePanel.add(folderNameText);

        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = ++y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(winOLSFileLabel, gbc);
        this.add(winOLSFileLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy =y;
        gbc.insets.left = 5;
        gbc.insets.bottom = 5;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(winolsScriptField, gbc);
        this.add(winolsScriptField);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy =y;
        gbc.insets.left = 5;
        gbc.insets.right = 10;
        gbc.insets.bottom = 5;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(winOLSBrowseButton, gbc);
        this.add(winOLSBrowseButton);

        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = ++y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(exampleFirmwareFileLabel, gbc);
        this.add(exampleFirmwareFileLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 5;
        gbc.insets.bottom = 5;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(exampleFirmwareFileField, gbc);
        this.add(exampleFirmwareFileField);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 5;
        gbc.insets.right = 10;
        gbc.insets.bottom = 5;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(exampleFileBrowseButton, gbc);
        this.add(exampleFileBrowseButton);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = ++y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(reuseAnalysisCheckbox, gbc);
        this.add(reuseAnalysisCheckbox);

        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = ++y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(inputFilesLabel, gbc);
        this.add(inputFilesLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 5;
        gbc.insets.bottom = 5;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(inputFilesField, gbc);
        this.add(inputFilesField);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 5;
        gbc.insets.right = 10;
        gbc.insets.bottom = 5;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(inputFilesBrowseButton, gbc);
        this.add(inputFilesBrowseButton);

        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = ++y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(outputFilesLabel, gbc);
        this.add(outputFilesLabel);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 5;
        gbc.insets.bottom = 5;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(outputFilesField, gbc);
        this.add(outputFilesField);

        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 5;
        gbc.insets.right = 10;
        gbc.insets.bottom = 5;
        gbc.anchor = GridBagConstraints.EAST;
        gbl.setConstraints(outputFilesBrowseButton, gbc);
        this.add(outputFilesBrowseButton);

        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = ++y;
        gbc.anchor = GridBagConstraints.SOUTH;
        gbl.setConstraints(processButton, gbc);
        this.add(processButton);

    }

    public List<File> getSelectedFiles(String fieldName) {
        return selectedFiles.get(fieldName);
    }

    private void displayFileChooser(JTextField fileField,
                                    String title,
                                    String approveButtonText,
                                    String approveButtonTooltTipText,
                                    GhidraFileChooserMode fileChooserMode,
                                    boolean multiSelectionEnabled) {
        GhidraFileChooser fileChooser = this.fileChoosers.get(fileField.getName());
        if (fileChooser == null) {
            fileChooser = createFileChooser(fileField.getName(), fileChooserMode, multiSelectionEnabled);
        }
        fileChooser.setTitle(title);
        fileChooser.setApproveButtonText(approveButtonText);
        fileChooser.setApproveButtonToolTipText(approveButtonTooltTipText);

        List<File> files = fileChooser.getSelectedFiles();
        if (multiSelectionEnabled) {
            fileField.setText(files.toString());
        } else if (!files.isEmpty()){
            fileField.setText(files.get(0).toString());
        }

        if ((files.size() == 1) && fileField.getName().equals(WinOLSPanel.WINOLSSCRIPT)) {
            Preferences.setProperty(WinOLSPreferences.LAST_WINOLS_SCRIPT_DIRECTORY, files.get(0).getParent());
        }

        selectedFiles.put(fileField.getName(), files);
    }

    private GhidraFileChooser createFileChooser(String name, GhidraFileChooserMode fileChooserMode, boolean multiSelectionEnabled) {
        GhidraFileChooser fileChooser = new GhidraFileChooser(this);
        fileChooser.setMultiSelectionEnabled(multiSelectionEnabled);
        File choice = new File(GenericRunInfo.getProjectsDirPath());
        String lastDirSelected =
                Preferences.getProperty(WinOLSPreferences.LAST_WINOLS_SCRIPT_DIRECTORY, null, true);
        if (lastDirSelected != null) {
            choice = new File(lastDirSelected);
        }
        fileChooser.setFileSelectionMode(fileChooserMode);
        fileChooser.setFileFilter(new GhidraFileFilter() {
            @Override
            public String getDescription() {
                return name;
            }

            @Override
            public boolean accept(File f, GhidraFileChooserModel model) {
                if (name.equals(WinOLSPanel.INPUTFILES) && "json".equals(FilenameUtils.getExtension(f.getName()))) {
                    return false;
                }
                return true;
            }
        });
        fileChooser.setCurrentDirectory(choice);//start the browsing in the user's preferred project directory

        this.fileChoosers.put(name, fileChooser);
        return fileChooser;
    }

    public boolean reuseAnalysis() {
        return reuseAnalysis;
    }
}
