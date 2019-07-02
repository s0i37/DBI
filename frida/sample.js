Process.enumerateThreadSync() 			// все потоки
Process.enumerateModulesSync() 			// all dlls
Process.enumerateRangesSync('r-x') 		// все секции с указанным доступом
Process.getRangeByAddress( ptr(0x10000000) ) 	// секция по адресу

Module.enumerateImportSync('msvcrt.dll') 			// импорт модуля

Memory.readByteArray( ptr(0x10000000), 100 )
Memory.readCString( ptr(0x10000000) )
f = new File('segment.dmp', 'wb') 								// дамп участка памяти в файл
f.write( Memory.readByteArray( ptr(0x10000000), 0x12000 ) )
f.close()

Interceptor.attach( new NativeFunction( ptr(0x401000), 'int', ['pointer','int'] ), 	// перехват вызова произвольной внутренней функции
	{
		onEnter: function(args) {console.log(args)}
	}
)

Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") 	// backtrace

Instruction.parse(ptr(0x00055cd8aedd000)).toString() 	// disas
