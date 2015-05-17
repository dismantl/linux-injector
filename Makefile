CFLAGS+=-std=c99 -D_GNU_SOURCE -g -O0
DEPS = Makefile

all: injector dummy print

%.o: %.c %.h $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

injector: inject.o ptrace.o main.o clone64.bin clone32.bin mmap64.bin mmap32.bin
	$(CC) $(CFLAGS) -o injector inject.o ptrace.o main.o $(LDFLAGS)

dummy: dummy.o
	$(CC) $(CFLAGS) -o dummy $^ $(LDFLAGS)

print: print.o print64.bin print32.bin
	$(CC) $(CFLAGS) -o print print.o $(LDFLAGS)

%.bin: %.asm $(DEPS)
	fasm $<

debug: CFLAGS+=-DDEBUG
debug: all

clean:
	rm -f injector dummy print *.o *.bin

.PHONY: all clean debug