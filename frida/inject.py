import frida
from sys import argv,stdin
import socket

if len(argv) != 3:
	print "%s PID|prog.exe instrument.js" % argv[0]
	exit()

def on_message(msg,data):
	s.sendto("crash 0x%x\n"%msg["payload"], ('10.0.0.1', 5555))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
device = frida.get_device('local')
for p in device.enumerate_processes():
	if argv[1] in [str(p.pid), p.name]:
		target = p.pid
session = device.attach(target)
script = session.create_script( open(argv[2]).read() )
script.on('message', on_message)
script.load()
stdin.read()