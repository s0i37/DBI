var once = false
function memdump(that)
{
	if(once)
		return
	once = true
	var out, modules = {}, name

	/* modules */
	out = new File("modules.txt", "w")
	Process.enumerateModulesSync().forEach(
		function(module)
		{
			modules[ module['name'] ] = { "start": parseInt(module['base']), "end": parseInt(module['base'])+module['size'] }
			out.write("oba " + module['base'] + " " + module['path'] + "\n")
		}
	)
	out.close()

	/* pages */
	Process.enumerateRangesSync('').forEach(
		function(page)
		{
			name = 'unknown'
			for(var module in modules)
				if(modules[module].start <= parseInt(page['base']) && parseInt(page['base']) <= modules[module].end)
				{
					name = module
					break
				}
			try
			{
				out = new File(page['base'] + "=" + page['protection'] + "=" + name + ".bin", "wb")
				out.write( Memory.readByteArray( ptr(parseInt(page['base'])), page['size'] ) )
				out.close()
				console.log("[+] " + page['base'] + "=" + page['protection'] + "=" + name + ".bin")
			}
			catch(e)
			{
				console.log("[-] " + page['base'] + "=" + page['protection'] + "=" + name + ".bin")
			}
		}
	)

	/* threads */
	out = new File('thread_current.txt', 'w')
	for(var reg in that['context'])
		out.write("ar " + reg + "=" + that['context'][reg] + "\n")
	out.close()
	Process.enumerateThreadsSync().forEach(
		function(thread)
		{
			out = new File('thread_' + thread['id'] + '.txt', 'w')
			for(var reg in thread['context'])
				out.write("ar " + reg + "=" + thread['context'][reg] + "\n")
			out.close()
		}
	)
}

//var addr = ptr(0x01487fab)
var addr = Module.getExportByName("libc.so.6","read")
var mem_changed = Memory.readByteArray(addr, 10)
Interceptor.attach( new NativeFunction( addr, 'int', [] ),
	{
		onEnter: function(args) {memdump(this)},
		//onLeave: function(retval) {memdump(this)}
	}
)
