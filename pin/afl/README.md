### Instrumentation for common fuzzing with AFL

#### Build

`make PIN_ROOT=/path/to/pin`

#### Instrument

`__AFL_SHM_ID=$((0x1337)) PIPE_SYNC=/opt/afl/afl_sync pin -follow_execv -pid 12345 -t /path/to/DBI/pin/afl/obj-intel64/cover.so -module libsome.so.0 -exit 0xd7c1`

#### Fuzzing

Fuzz with https://github.com/s0i37/afl

### Instrumentation for inmemory fuzzing with AFL

#### Build

`make PIN_ROOT=/path/to/pin`

#### Instrument

`__AFL_SHM_ID=1337 pin -pid $(pidof inmemory) -t /full/path/to/DBI/pin/afl/fuzz.so -module inmemory -entry 0x151 -exit 0x1d4`

#### Fuzzing

Fuzz with https://github.com/s0i37/afl_inmemory
