package pcodefiles.ui;

import docking.DialogComponentProvider;
import pcodefiles.model.Group;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.List;

public class SizeReuseDialog extends DialogComponentProvider {
    List<Group> groups = new ArrayList<>();
    private File sizeReuseFile;
    Map<String,String> sizeReuseMap = new HashMap<>();


    public SizeReuseDialog(File codePatternsFile, File sizeReuseFile) {
        super("Reuse map sizes from other maps");
        this.sizeReuseFile = sizeReuseFile;

        readGroups(codePatternsFile);

        this.addWorkPanel(new GroupSizePanel(groups, sizeReuseMap));
        this.addApplyButton();
    }

    private void readGroups(File codePatternsFile) {
        Scanner reader = null;
        try {
            reader = new Scanner(codePatternsFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();

            this.close();
            return;
        }
        while (reader.hasNextLine()) {
            var data = reader.nextLine().split("::");

            groups.add(Group.unserialize(data));
        }
        reader.close();
    }

    @Override
    protected void applyCallback() {
        if (sizeReuseFile.exists()) {
            sizeReuseFile.delete();
        }
        try {
            sizeReuseFile.createNewFile();
            var writer = new FileWriter(sizeReuseFile);
            for (Map.Entry<String, String> entry : sizeReuseMap.entrySet()) {
                writer.write(entry.getKey() + "::" + entry.getValue());
                writer.write(System.getProperty("line.separator"));
            }
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        this.close();
    }
}
