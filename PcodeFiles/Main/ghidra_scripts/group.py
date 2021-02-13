class GroupContainer:
	def __init__(self):
		self.groups = {}

	def get(self, groupId):
		return self.groups.setdefault(groupId, Group(groupId))

class Group:
	GROUP_TYPE_LIST = 0
	GROUP_TYPE_MAP_2D = 1
	GROUP_TYPE_MAP_3D = 2

	def __init__(self, id):
		self.id = id
		self.type = None
		self.sizes = {}
		self.folderName = ""

	def getId(self):
		return self.id

	def setName(self, name):
		self.name = name

	def getName(self):
		return self.name

	def setAddress(self, address):
		self.address = address

	def getAddress(self):
		return self.address

	def setDataOrg(self, dataOrg):
		self.dataOrg = dataOrg

	def getDataOrg(self):
		return self.dataOrg

	def setGroupType(self, type):
		self.type = type

	def getGroupType(self):
		return self.type

	def setSizes(self, x, y):
		self.sizes = {'x': x, 'y': y}

	def getSizes(self):
		return self.sizes

	def setFolderName(self, folderName):
		self.folderName = folderName

	def getFolderName(self):
		return self.folderName

	# in bytes
	def getDataTypeSize(self):
		if "eByte" == self.dataOrg:
			return 1
		elif self.dataOrg in ['eLoHi', 'eHilo']:
			return 2
		elif self.dataOrg in ['eLoHiLoHi', 'eHiLoHiLo']:
			return 4
		elif self.dataOrg in ['eFloatLoHi', 'eFloatHiLo']:
			return 8
