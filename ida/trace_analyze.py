import sys
from os.path import basename

tracefile = sys.argv[1]

with open(tracefile, 'r') as f:
	modules = {}
	for line in f:
		if line.startswith('module'):
			entries = line.split(' ')
			low_addr = entries[1]
			high_addr = entries[2]
			path = entries[-1:][0].split()[0]
			modules[ basename(path) ] = [ int(low_addr[2:10], 16), int(high_addr[2:10], 16) ]
		else:
			try:
				eip = int( line.split(' ')[0][2:10], 16 )
				for module,ranges in modules.items():
					if eip >= ranges[0] and eip < ranges[1]:
						print "%s+%x" % ( module, eip-ranges[0] )
			except:
				pass
