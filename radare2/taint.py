import r2pipe
import sys

taint_log_file = sys.argv[1]
#calls_log_file = sys.argv[1]
r2 = r2pipe.open()

tainted_instructions = {}

'''def create_function():
	with open( calls_log_file, 'r' ) as f:
		for line in f:
			line = line.split('\r\n')[0]
			try:
				eip = int(line[2:10], 16)
				r2.cmd( "af %s @ %d" % ( "process_" + hex(eip)[2:], eip ) )
			except Exception as e:
				print str(e)'''


def highlight_taint():
	i = 0
	j = 0
	with open( taint_log_file, 'r' ) as f:
		r2.cmd("fz taint")
		r2.cmd("fs taint")
		for line in f:
			line = line.split('\r\n')[0]
			try:
				eip = int(line[2:10], 16)
				words = line.split(' ')
				r2.cmd( "f tainted_instr%d @ %d" % (i, eip) )
				function_name = r2.cmd("afn @ %d" % eip)

				if r2.cmd("afn @ %d" % eip).find("_taint_") == -1:
					function_name =  "%s_taint_%d" % (function_name, j)
					r2.cmd( "afn %s @ %d" % (function_name, eip ) )
					j += 1

				comment = 'taint: ' + ' '.join( words[1:] )
				r2.cmd( "s %d" % eip )
				r2.cmd( "CC '%s'" % comment.replace('>', '\\x3e') )
				r2.cmd( "ecHi red" )
				i += 1

				eip = "0x%08x" % eip
				try:
					tainted_instructions[ function_name ].append( (eip,comment) )
				except:
					tainted_instructions[ function_name ] = [ (eip,comment) ]
			except Exception as e:
				print str(e)


def plot_tainted_functions():
	import pydot
	for function,taints in tainted_instructions.items():
		dotfile = "{}.dot".format(function)
		print 'create %s' % dotfile
		with open(dotfile, 'w') as o:
			o.write( r2.cmd( "ag {0}".format(function) ) )

		graph = pydot.graph_from_dot_file( dotfile )[0]
		for (eip,comment) in taints:
			for node in graph.get_node_list():
				if node.get_label() and node.get_label().find( eip ) != -1:
					node.set_label( node.get_label().replace( eip, "%s\n%s" % (comment,eip) ) )
					node.set_fillcolor('yellow')
		graph.write_dot( dotfile )

if __name__ == '__main__':
	highlight_taint()
	plot_tainted_functions()
	#create_function()