import sys

this = sys.modules[__name__]

def clean_hex(d):
	'''
     Convert decimal to hex and remove the "L" suffix that is appended to large
     numbers
     '''
	return hex(d).rstrip('L')