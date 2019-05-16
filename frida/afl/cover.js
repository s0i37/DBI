
Interceptor.attach( new NativeFunction( ptr(0x0000563729465099), 'void', [] ),
	{
		onEnter: function(args) { send(0x0000563729465099) }
	}
)