var known_exc = [0x1412036,0x1412046,0x14121ff,0x14122ff]
function onExc(v) {
	if(v["type"] == "access-violation" && known_exc.indexOf( parseInt(v["context"]["pc"]) ) == -1 )
	{
		console.log("[!] exception: " + v["type"] + " " +
			" - " + v["memory"]["operation"] + " " + v["memory"]["address"] +
			" in RIP=" + v["context"]["pc"])
		send( parseInt(v["context"]["pc"]) )
	}
	return false // pass to the application
}
Process.setExceptionHandler(onExc)
console.log("ready")
