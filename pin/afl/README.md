Instrumentation for inmemory fuzzing with afl

#### Build

`make PIN_ROOT=/path/to/pin`

#### Instrument

`__AFL_SHM_ID=1337 pin -pid $(pidof inmemory) -t /full/path/to/DBI/pin/afl/fuzz.so -module inmemory -entry 0x151 -exit 0x1d4`

#### Fuzzing

Fuzz through https://github.com/s0i37/afl
