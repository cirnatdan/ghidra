from pcodefiles.model import Group


class GroupContainer:
    def __init__(self):
        self.groups = {}

    def get(self, groupId):
        return self.groups.setdefault(groupId, Group(groupId))
