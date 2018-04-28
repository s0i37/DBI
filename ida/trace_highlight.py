import re
from idaapi import *
from idautils import *
from idc import *
import os

traces_dir = r"C:\Users\user\Desktop\FUZZ\traces"
RED = 0xaaaaff
GREEN = 0xaaffaa
GREEN_DARK = 0x22aa22
CYAN = 0xdddd00
BLUE = 0xffaaaa
YELLOW = 0x007777
GREY = 0xbbbbbb
WHITE = 0xffffff

segments = []
for segment in Segments():
	segments.append( segment )
MIN = min(segments) & 0xfffff000
MAX = max(segments) | 0x00000fff

def _get_registers(line):
	try:
		return re.match(".*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line).groups()
	except:
		return None,None,None,None,None,None,None,None,


def reset_colors():
	for segment in Segments():
		for element in Heads( segment, SegEnd(segment) ):
			if isCode( GetFlags(element) ):
				SetColor( element, CIC_ITEM, WHITE )

def _get_gradient(addr, base_color):
	current_color = GetColor(addr, CIC_ITEM)
	red = current_color & 0xff
	green = current_color >> 8 & 0xff
	blue = current_color >> 16 & 0xff
	if base_color == 'red':
		blue = blue - 0x10 if blue > 0x10 else blue
		green = green - 0x10 if green > 0x10 else green
		return (blue << 16) + (green << 8) + red
	elif base_color == 'green':
		blue = blue - 0x10 if blue > 0x10 else blue
		red = red - 0x10 if red > 0x10 else red
		return (blue << 16) + (green << 8) + red 
	elif base_color == 'blue':
		green = green - 0x10 if green > 0x10 else green
		red = red - 0x10 if red > 0x10 else red
		return (blue << 16) + (green << 8) + red

def colorize_trace(trace_file, base_color, with_rename=''):
	function_names = set()
	need_comment = 0
	with open( trace_file, "rb") as f:
		for line in f.read().split("\r\n"):
			try:
				eip = int(line[2:10], 16)
				if MIN <= eip <= MAX:
					SetColor( eip, CIC_ITEM, _get_gradient(eip, base_color) )
					function_names.add( GetFunctionName(eip) )
					'''
					eax,edx,ecx,ebx,esi,edi,ebp,esp = _get_registers(line)
					if need_comment:
						set_cmt( need_comment, "ecx=%s" % ecx, 1 )
						print "0x%08x: %s" % (need_comment,ecx)
						need_comment = 0
					if GetDisasm(eip).find("mov") == 0 and GetDisasm(eip).find("ecx,") != -1:
						need_comment = eip
					elif GetDisasm(eip).find("mov") == 0 and GetDisasm(eip).find("esi,") != -1 and GetDisasm(eip).find("ecx") != -1:
						set_cmt( eip, "esi=%s" % ecx, 1 )
						print "0x%08x: %s" % (eip,ecx)
					'''
			except Exception as e:
				pass
	if with_rename:
		num = 0
		new_function_names = []
		for function_name in function_names:
			try:
				MakeName( LocByName(function_name), with_rename + str(num) )
				new_function_names.append( with_rename + str(num) )
			except:
				pass
			num += 1
		function_names = new_function_names

	print 'covered %d functions:' % len(function_names)
	print ', '.join(function_names)


def colorize_taint(addrs_file, color, with_rename=''):
	function_names = []
	commented = set()
	with open( addrs_file, "rb") as f:
		for line in f.read().split("\r\n"):
			try:
				words = line.split(' ')
				eip = int( words[0][2:10], 16 )
				function_name = GetFunctionName(eip)
				if not function_name in function_names:
					function_names.append(function_name)
				SetColor( eip, CIC_ITEM, color )
				comment = ' '.join( words[1:] )
				if comment:
					set_cmt( eip, comment, 0 ) if not eip in commented else set_cmt( eip, GetCommentEx(eip, 0) + '\n' + comment, 0 )
					commented.add(eip)
			except Exception as e:
				pass

	if with_rename:
		num = 0
		new_function_names = []
		for function_name in function_names:
			try:
				new_function_name = with_rename + str(num)
				MakeName( LocByName(function_name), new_function_name )
				new_function_names.append(new_function_name)
			except:
				pass
			num += 1
		function_names = new_function_names

	print "affected %d functions:" % len(function_names)
	for function_name in function_names:
		print function_name


reset_colors()
#colorize_trace( os.path.join(traces_dir, "trace-rnautility_dll-recv.txt"), base_color='green', with_rename='do_recv' )
#colorize_trace( os.path.join(traces_dir, "trace-rnautility_dll-idle.txt"), base_color='blue', with_rename='idle' )
colorize_taint( os.path.join(traces_dir, 'taint-rnautility_dll-mtype.txt'), color=YELLOW, with_rename='taint' )

