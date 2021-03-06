import frida
from sysv_ipc import SharedMemory
from struct import pack,unpack
from sys import argv, stdin


if len(argv) != 3:
	print "%s PID|prog instrument.js"
	exit()

def on_message(msg, data):
	try:
		bb = msg['payload']
		print bb
		byte = unpack( 'B', shm.read(1, bb%0x10000) )[0]
		shm.write( pack('B', (byte+1)%0x100), bb%0x10000 )
	except Exception as e:
		print msg

JS = open( argv[2] ).read()
SHM_KEY = 0x20137
shm = SharedMemory(SHM_KEY)

device = frida.get_device('local')
for p in device.enumerate_processes():
	if argv[1] in [str(p.pid), p.name]:
		target = p.pid

session = device.attach(target)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
stdin.read()