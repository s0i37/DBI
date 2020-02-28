Process.enumerateThreadSync() 			// все потоки
Process.enumerateModulesSync() 			// all dlls
Process.enumerateRangesSync('r-x') 		// все секции с указанным доступом
Process.getRangeByAddress( ptr(0x10000000) ) 	// секция по адресу

Module.enumerateImportsSync('msvcrt.dll') 			// импорт модуля
Module.enumerateExportsSync('msvcrt.dll') 			// экспорт модуля
Module.getExportByName("msvcrt.dll","malloc") 		// адрес функции

Memory.readByteArray( ptr(0x10000000), 100 )
Memory.readCString( ptr(0x10000000) )
f = new File('segment.dmp', 'wb') 								// дамп участка памяти в файл
f.write( Memory.readByteArray( ptr(0x10000000), 0x12000 ) )
f.close()

intercept = Interceptor.attach( new NativeFunction( ptr(0x401000), 'int', ['pointer','int'] ), 	// перехват вызова произвольной функции
	{
		onEnter: function(args) {console.log("func(" + args[0]+","+args[1] + ")")},
		onLeave: function(retval) {console.log("func() -> " + retval)}
	}
)
intercept.detach()

Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") 	// backtrace

Instruction.parse(ptr(0x00055cd8aedd000)).toString() 	// disas


/* размер всей виртуальной памяти */
mem=0
Process.enumerateRangesSync('').forEach(function(page) { mem+=page["size"] })

/* exception handling */
function onExc(v) {
	console.log("[*] exception: " + v["type"] + " " +
		" - " + v["memory"]["operation"] + " " + v["memory"]["address"] +
		" in RIP=" + v["context"]["pc"] + " RSP=" + v["context"]["sp"])
	return false // pass to the application
}
Process.setExceptionHandler(onExc)



/*
В Interceptor.attach() в событии onEnter/onLeave дополнительно доступны:
	this = {
		returnAddress:
		threadId:
		depth:
		context: {
			eax:,
			ecx:,
			...
		}
	}
*/