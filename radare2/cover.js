#!/usr/local/bin/node

const r2pipe = require("r2pipe"),
	process = require("process"),
	fs = require("fs")

if( process.argv.length != 4 )
{
	console.log( process.argv[1] + " cover.txt color")
	return
}

var r2 = r2pipe.open(),
	cover = process.argv[2],
	color = process.argv[3],
	basic_blocks = fs.readFileSync(cover).toString().split('\n')

for(var i = 0; i < basic_blocks.length; i++)
{
	if(! basic_blocks[i].trim() )
		continue
	r2.cmd( "s section..text + " + basic_blocks[i] )
	console.log( r2.cmd("s") )
	r2.cmd( "ecH- @@s:$Fb $Fb+$Fs 1" )
	r2.cmd( "ecHi " + color + " @@s:$Fb $Fb+$Fs 1" )
}