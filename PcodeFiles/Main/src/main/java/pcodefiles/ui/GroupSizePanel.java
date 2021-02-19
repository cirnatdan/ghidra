package pcodefiles.ui;

import pcodefiles.model.Group;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class GroupSizePanel extends JPanel {

    public GroupSizePanel(List<Group> groups, Map<String,String> sizeReuseMap) {

        GridBagLayout gbl = new GridBagLayout();
        this.setLayout(gbl);
        int y = 0;

        var gbc = new GridBagConstraints();
        var groupIdLabel = new Label("Group Id");
        var groupNameLabel = new Label("Group Name");
        var groupSizeLabel = new Label("Computed original size");
        var sizeFromLabel = new Label("Use size from");

        gbc.gridx = 0;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(groupIdLabel, gbc);
        this.add(groupIdLabel);

        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(groupNameLabel, gbc);
        this.add(groupNameLabel);

        gbc.gridx = 2;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(groupSizeLabel, gbc);
        this.add(groupSizeLabel);

        gbc.gridx = 3;
        gbc.gridy = y;
        gbc.insets.left = 10;
        gbc.anchor = GridBagConstraints.WEST;
        gbl.setConstraints(sizeFromLabel, gbc);
        this.add(sizeFromLabel);

        y++;

        var groupList = groups.stream().map(Group::getId).collect(Collectors.toList());

        for (var group: groups) {
            groupIdLabel = new Label(group.getId());
            groupNameLabel = new Label(group.getName());
            groupSizeLabel = new Label(String.valueOf(group.getSizes().get("x")));


            var groupComboBox = new JComboBox(groupList.toArray());
            groupComboBox.setSelectedIndex(y - 1);
            groupComboBox.addActionListener(e -> {
                sizeReuseMap.put(group.getId(), Objects.requireNonNull(groupComboBox.getSelectedItem()).toString());
            });

            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            gbl.setConstraints(groupIdLabel, gbc);
            this.add(groupIdLabel);

            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            gbl.setConstraints(groupNameLabel, gbc);
            this.add(groupNameLabel);

            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            gbl.setConstraints(groupSizeLabel, gbc);
            this.add(groupSizeLabel);

            gbc = new GridBagConstraints();
            gbc.gridx = 3;
            gbc.gridy = y;
            gbc.insets.left = 10;
            gbc.anchor = GridBagConstraints.WEST;
            gbl.setConstraints(groupComboBox, gbc);
            this.add(groupComboBox);

            y++;
        }
    }
}
