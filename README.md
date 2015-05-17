# linux-injector
Utility for injecting executable code into a running process on x86/x64 Linux. It uses `ptrace()` to attach to a process, then `mmap()`'s memory regions for the injected code, a new stack, and space for trampoline shellcode. Finally, the trampoline in the target process is used to create a new thread and execute the chosen shellcode, so the main thread is allowed to continue. This project borrows from a number of other projects and research, see References below.

## Requirements
* [fasm][], the flat assembler

## Building
With [fasm][] installed in your `PATH`, simply run:
```
make
```
## Included programs and files
* **print**: Test program for executing shellcode using a variety of techniques: `fork()`, `clone()`, clone syscall with inline assembly.
* **dummy**: A trivial program for injecting into. Prints a message every second, then sleeps.
* **injector**: The main program for injecting executable code into a running process. Simply provide it with the PID of the process to inject into, and the shellcode to execute:

  `./injector 1234 print64.bin`

* **clone64.asm, clone32.asm, mmap64.asm, mmap32.asm**: Shellcode stubs used by the injector.
* **print64.asm, print32.asm**: Sample shellcode for printing a single line to stdout. Useful for testing the injector.

## References
* [Linux Threads Through a Magnifier: Local Threads](http://syprog.blogspot.com/2012/03/linux-threads-through-magnifier-local.html)
* [Linux Threads Through a Magnifier: Remote Threads](http://syprog.blogspot.com/2012/03/linux-threads-through-magnifier-remote.html)
* [Jugaad thread injection kit](https://github.com/aseemjakhar/jugaad)
* https://sourceware.org/ml/libc-help/2009-05/msg00090.html
* [Ptrace protection since Ubuntu 10.10](https://wiki.ubuntu.com/SecurityTeam/Roadmap/KernelHardening#ptrace_Protection)
* [Single Process Parasite: The quest for the stealth backdoor](http://www.phrack.org/issues/68/9.html)


## Further work
I plan on expanding this project to be a full ELF shared library injector. While this tool could theoretically be used as-is to inject a statically-compiled, position-independent ELF library, I want to be able to parse libraries with dynamically-loaded dependencies and load those dependencies as part of the injection process. The following resources are a useful starting point:
* [Injectso](http://c-skills.blogspot.com/2010/02/new-injectso-debian-proof.html)
* [Dynamically inject a shared library into a running process on Android/ARM](http://www.evilsocket.net/2015/05/01/dynamically-inject-a-shared-library-into-a-running-process-on-androidarm/)
* [ELF file format](http://flint.cs.yale.edu/cs422/doc/ELF_Format.pdf)
* [The Inside Story on Shared Libraries and Dynamic Loading](http://cseweb.ucsd.edu/~gbournou/CSE131/the_inside_story_on_shared_libraries_and_dynamic_loading.pdf)

Copyright (c) 2015, Dan Staples. This code is available under the [GNU General Public License, version 3](https://www.gnu.org/copyleft/gpl.html).

[fasm]: http://flatassembler.net/
