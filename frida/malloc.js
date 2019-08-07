{
	onEnter: function(log, args, state)
	{
		state.size = args[0]			// state - пустой объект для передачи данных между колбэками
	},
	onLeave: function(log, retval, state)
	{
		log("malloc(" + state.size + ") -> " + retval + " from " + this.returnAddress)
	}
}
