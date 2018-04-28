import r2pipe

def get_args(data):
	args = set()
	for line in data.split('\n'):
		try:
			stack_var = line.split(' ')[2]
			if 'arg' in stack_var:
				args.add(stack_var)
		except:
			pass
	return args

r2 = r2pipe.open()

old_addr = r2.cmd('afo')
r2.cmd('fs functions')
for line in r2.cmd('f~process').split('\n'):
	addr = line.split()[0]
	r2.cmd('s %s' % addr)
	args = get_args( r2.cmd('afvs') ) | get_args( r2.cmd('afvb') )
	if args:
		print "%s: %s" % ( addr, ', '.join(args) )
r2.cmd('s %s' % old_addr)