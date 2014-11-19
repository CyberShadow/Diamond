Diamond: D Memory Debugger
==========================

Diamond is a memory debugger and profiler for the D programming language.

It has the following components:

 * [a modified runtime (Druntime fork)](https://github.com/CyberShadow/druntime/tree/diamond)
 * a post-mortem memory log analyzer, which allows inspecting generated memory logs

The modified runtime logs all memory operations to a binary log file,
as well as periodic memory snapshots (before garbage collects).
Some logging options are configurable.

Diamond aims to mainly facilitate debugging memory leaks (data referenced by bogus pointers).

D2 support is still under development. The D1 version can be found on the d1 branch.

The log file format may change as development continues.

### Diamond runtime configuration

 * Set `DIAMOND_LOG` to something to enable writing a binary log.
 * Optionally, set `DIAMOND_LOGFILE` to the file name for the binary log,
   or `DIAMOND_LOGDIR` to the directory to which it will be written.

### Diamond runtime API

 * TODO (see `core.diamond.api`)

### Log analyzer features

 * TODO: update for D2
 * uses map files to display symbols in call stacks
 * can seek through the log file, allowing to examine the application state at different points in time
 * can display "top allocators" - call stacks that allocated most bytes
 * can filter memory events by address range
 * can display a [visual "memory map"](http://dump.thecybershadow.net/36ee988fc564aa9ab5529d43662eec81/0000062E.png) (useful for quickly finding large areas the GC shouldn't be scanning for pointers)
 * can search for references (pointers) to a certain memory range
 * can dump a region of memory to screen

### Future plans

 * better documentation
 * more type information (by hooking higher-level allocators)

How to use
==========

 1. Build D with the Diamond Druntime fork.
    E.g. using [Digger](https://github.com/CyberShadow/Digger):
    `digger build master+CyberShadow/druntime/diamond`
 2. If you enabled memory event logs, enable map file generation in your linker options.
 3. Rebuild your project with the `-g` and `-gs` compiler flags.
 4. Set the `DIAMOND_LOG` environment variable.
 5. Run your project as usual.
 6. Run the memory analyzer when the program terminates.

For better stack traces, you'll need to rebuild Phobos with symbols (add `-g -gs` to the relevant makefile).
