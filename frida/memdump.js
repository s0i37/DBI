var once = false
function memdump(that)
{
	if(once)
		return
	once = true
	var out

	console.log("[*] memory dumping")
	Process.enumerateRangesSync('').forEach(
		function(page)
		{
			try
			{
				out = new File(page['base'] + "=" + page['protection'] + "=page.bin", "wb")
				out.write( Memory.readByteArray( ptr(parseInt(page['base'])), page['size'] ) )
				out.close()
				console.log("[+] " + page['base'] + "=" + page['protection'] + "=page.bin")
			}
			catch(e)
			{
				console.log("[-] " + page['base'] + "=" + page['protection'] + "=page.bin")
			}
		}
	)

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

	out = new File("modules.txt", "w")
	Process.enumerateModulesSync().forEach(
		function(module)
		{
			out.write("oba " + module['base'] + " " + module['path'] + "\n")
		}
	)
	out.close()
}

var addr = Module.getExportByName("libc.so.6","read") 
Interceptor.attach( new NativeFunction( addr, 'int', [] ),
	{
		//onEnter: function(args) {memdump()},
		onLeave: function(retval) {memdump(this)}
	}
)
