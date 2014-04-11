Diamond: D Memory Debugger
==========================

Diamond is a post-mortem memory debugger and profiler. It is composed of two parts:

 * a module, which should be imported before any other modules in the project to be debugged
 * a memory log analyzer, which allows inspecting generated memory logs

The module logs all memory operations to a file, as well as periodic memory snapshots (before garbage collects). Some logging options are configurable.

Diamond aims to facilitate debugging memory leaks (data referenced by bogus pointers), memory corruption and other problems. It was written for D1 (both Phobos and Tango), D2 support is untested at best.

The project is not yet complete, but still usable. The log file format may change as development continues.

### Runtime module features

 * logs all memory events, with timestamps and call stacks
 * exports C functions, allowing debuggee to make memory maps or snapshots at any time, as well as log text comments
 * has optional memory debugging features, like checking free calls and stomping on deallocated memory

### Log analyzer features

 * uses map files to display symbols in call stacks
 * can seek through the log file, allowing to examine the application state at different points in time
 * can display "top allocators" - call stacks that allocated most bytes
 * can filter memory events by address range
 * can display a [visual "memory map"](http://dump.thecybershadow.net/36ee988fc564aa9ab5529d43662eec81/0000062E.png) (useful for quickly finding large areas the GC shouldn't be scanning for pointers)
 * can search for references (pointers) to a certain memory range
 * can dump a region of memory to screen

### Limitations

 * limited support for multi-threaded programs
 * limited by design to 32-bit architectures
 * poor support for allocations in destructors

### Future plans

 * better documentation
 * more type information (by hooking higher-level allocators)
 * more runtime library options
 * better multi-threaded support
 * use of CodeView instead of map files to allow symbolic examination of objects
 * possibly, more means to detect/debug memory corruption
 * possibly a major revision as a replacement runtime, rather than a normal module

How to use
==========

 1. Copy `diamond.d` to your project's directory
 2. Adjust options defined at the top of `diamond.d`
 3. Add `import diamond;` before other imports in your project's main module
 4. If you enabled memory event logs, enable map file generation in your linker options.
 5. To build you will need to pass an import path to Druntime's `src` directory (e.g. -IC:\D\dmd2\src\druntime), since `diamond.d` requires the modules in the `gc` directory.
 6. Rebuild and run your project as usual.
 7. If you enabled memory event logs, run the memory analyzer when the program terminates.

For correct stack traces, you'll need to rebuild Phobos with symbols (add `-g` and remove `-O` from the `DFLAGS` option in the makefiles).

### API

You can use the following functions in your code to log information to the memory event log on-demand:

 * `extern(C) public void logMemoryDump(bool dataDump, Gcx* gcx = null)` - On-demand memory dump. `dataDump` controls whether the memory contents is dumped, otherwise only meta-information is saved.
 * `extern(C) public void logText(char[] text)` - log an arbitrary text string.
 * `extern(C) public void logNumber(uint n)` - log a number as text (helper function).

The functions are defined as extern(C), so that they can be called anywhere in the program, without having to import the `diamond` module (e.g. in the runtime or standard library).
