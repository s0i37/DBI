from idaapi import *
from idautils import *
from idc import *
from json import loads
import re

RED = 0x000044
GREEN = 0x004400
CYAN = 0x444400
WHITE = 0xffffff

def reset_colors():
	for segment in Segments():
		for element in Heads( segment, SegEnd(segment) ):
			if isCode( GetFlags(element) ):
				SetColor( element, CIC_ITEM, WHITE )

def set_gradient(eip, color):
	SetColor( eip, CIC_ITEM, color )

def get_gradient(addr):
	current_color = GetColor(addr, CIC_ITEM)
	red = current_color & 0xff
	green = current_color >> 8 & 0xff
	blue = current_color >> 16 & 0xff
	return (blue << 16) + (green << 8) + red

def get_bb_bounds(eip):
	func = get_func(eip)
	if func:
		for bb in FlowChart( func ):
			if bb.startEA <= eip <= bb.endEA:
				return (bb.startEA, bb.endEA)

reset_colors()
functions = set()
i = 0
with open("/root/.documents/fuzz/slssvc/out/coverages.jl", "r") as f:
	cov_id = 0
	bblocks = {}
	for line in f:
		json_start = line.index("{")
		coverage = loads( line[json_start: ] )
		print cov_id
		for bb_id in coverage.keys():
			iters = int( coverage[bb_id] )
			eip = 0x401000 + int(bb_id)
			bounds = get_bb_bounds(eip)
			if bounds:
				try:
					bblocks[ bounds[0] ][0].append( "%d(%d)" % (cov_id, iters) )
				except:
					bblocks[ bounds[0] ] = [ [], int(bb_id) ]
					bblocks[ bounds[0] ][0] = [ "%d(%d)" % (cov_id, iters) ]

				for addr in xrange( *bounds ):
					set_gradient( addr, GREEN )

			else:
				set_gradient( addr, GREEN )
				print "[!] unknown bb in 0x%x" % eip

			function_name = GetFunctionName(eip)
			if not function_name:
				print "[!] unknown function at 0x%x" % eip
			if not function_name in functions:
				MakeName( LocByName(function_name), "covered_function_%d" % i )
				functions.add( "covered_function_%d" % i )
				i += 1
		cov_id += 1

for (bb,opts) in bblocks.items():
	(cmt,bb_id) = opts
	ExtLinA( bb, 0, "%d covered: %d" % ( bb_id, len(cmt) ) )
