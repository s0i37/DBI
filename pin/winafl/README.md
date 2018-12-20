Instrumentation for inmemory fuzzing with winafl

#### Build for x64/x86 respectively

`make all TARGET=intel64`

`make all TARGET=ia32`

#### Instrument

`pin.exe -pid 1234 -t c:\path\to\PIN\winafl\fuzz.dll -module inmemory.exe -entry 0x13 -exit 0xd1`

#### Fuzzing

Fuzz through https://github.com/s0i37/winafl
