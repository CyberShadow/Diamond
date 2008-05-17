module diamond;

version = MEMSTOMP;  // stomp on memory when it's freed
version = FREECHECK; // checks manual delete operations
version = MEMLOG;    // log memory operations and content 
//version = MEMLOG_VERBOSE; // save memory dumps before and after every allocation - use only on very short test cases
const LOGDIR = ``;   // path prefix for memory logs

private:

version(Tango)
{
	import tango.core.Memory;
	import tango.stdc.stdio;
	import tango.stdc.stdlib : stdmalloc = malloc;
	version(Windows) import tango.sys.win32.UserGdi;
	else import tango.stdc.posix.sys.mman;
	version(MEMLOG) import tango.stdc.time;

	// IMPORTANT: add .../tango/lib/gc/basic to the module search path
	import gcbits;
	import gcx;
	import gcstats;
	alias gcx.GC GC;

    extern (C) void* rt_stackBottom();
    alias rt_stackBottom os_query_stackBottom;

	extern(C) extern void* D2gc3_gcC3gcx2GC;
	alias D2gc3_gcC3gcx2GC gc;
}
else
{
	import std.gc;
	import std.c.stdio;
	import std.c.stdlib : stdmalloc = malloc;
	version(Windows) import std.c.windows.windows;
	else import std.c.linux.linux;
	version(MEMLOG) import std.c.time;

	// IMPORTANT: if the imports below don't work, remove "internal.gc." and add ".../dmd/src/phobos/internal/gc" to the module search path
	version (Win32) import internal.gc.win32;
	version (linux) import internal.gc.gclinux;
	import internal.gc.gcbits;
	import internal.gc.gcx;
	import gcstats;
	alias getGCHandle gc;
}

struct Array
{
    size_t length;
    byte *data;
}

// ****************************************************************************

void** ebp()
{
	asm
	{
		naked;
		mov EAX, EBP;
		ret;
	}
}

public void printStackTrace()
{
	auto bottom = os_query_stackBottom();
	for(void** p=ebp();p;p=cast(void**)*p)
	{
		printf("%08X\n", *(p+1));
		if(*p <= p || *p > bottom)
			break;
	}
}

version(MEMLOG)
{
	FILE* log;

	void logDword(uint  i) { fwrite(&i, 4, 1, log); }		
	void logDword(void* i) { fwrite(&i, 4, 1, log); }
	void logData(void[] d) { fwrite(d.ptr, d.length, 1, log); }
	void logBits(ref GCBits bits) { logDword(bits.nwords); if(bits.nbits) logData(bits.data[1..1+bits.nwords]); }

	void logStackTrace()
	{
		auto bottom = os_query_stackBottom();
		for(void** p=ebp();p;p=cast(void**)*p)
		{
			if(*(p+1))
				logDword(*(p+1));
			if(*p <= p || *p > bottom)
				break;
		}
		logDword(null);
	}
	
	enum : int
	{
		PACKET_MALLOC,
		PACKET_CALLOC,
		PACKET_REALLOC,
		PACKET_EXTEND,
		PACKET_FREE,
		PACKET_MEMORY_DUMP,
		PACKET_MEMORY_MAP,
		PACKET_TEXT,
	}

	Object logsync;
}

// ****************************************************************************

version(Windows)
{
	bool makeWritable(void* address, size_t size)
	{
		uint old; 
		return VirtualProtect(address, size, PAGE_EXECUTE_WRITECOPY, &old) != 0;
	}
}
else
{   
	extern (C) int sysconf(int);	
	bool makeWritable(void* address, size_t size)
	{
		const _SC_PAGE_SIZE = 30;  // IMPORTANT: may require changing on your platform, look it up in your C headers
		uint pageSize = sysconf(_SC_PAGE_SIZE);
		address = cast(void*)((cast(uint)address) & ~(pageSize-1));
		int pageCount = (cast(size_t)address/pageSize == (cast(size_t)address+size_t)/pageSize) ? 1 : 2;
		return mprotect(address, pageSize * pageCount, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
	}
}

static uint calcDist(void* from, void* to) { return cast(ubyte*)to - cast(ubyte*)from; }

template Hook(TargetType, HandlerType)
{
	static ubyte[] target;
	static ubyte[5] oldcode, newcode;
	static void initialize(TargetType addr, HandlerType fn)
	{
		target = cast(ubyte[])(cast(void*)addr)[0..5];
		oldcode[] = target;
		newcode[0] = 0xE9; // long jump
		*cast(uint*)&newcode[1] = calcDist(target.ptr+5, fn);
		auto b = makeWritable(target.ptr, target.length);
		assert(b);
		hook();
	}

	static void hook() { target[] = newcode; }
	static void unhook() { target[] = oldcode; }
}

/// Hook a function by overwriting the first bytes with a jump to your handler. Calls the original by temporarily restoring the hook (caller needs to do that manually due to the way arguments are passed on).
/// IMPORTANT: this may only work with the calling conventions specified in the D documentation ( http://www.digitalmars.com/d/1.0/abi.html ), thus may not work with GDC
struct FunctionHook(int uniqueID, ReturnType, Args ...)
{
	mixin Hook!(ReturnType function(Args), ReturnType function(Args));
}

/// The last argument of the handler is the context.
struct MethodHook(int uniqueID, ReturnType, ContextType, Args ...)
{
	mixin Hook!(ReturnType function(Args), ReturnType function(Args, ContextType));
}

/// Hook for extern(C) functions.
struct CFunctionHook(int uniqueID, ReturnType, Args ...)
{
	extern(C) alias ReturnType function(Args) FunctionType;
	mixin Hook!(FunctionType, FunctionType);
}

MethodHook!(1, size_t, Gcx*, void*) fullcollectHook;
version(MEMSTOMP)
{
	CFunctionHook!(2, byte[], TypeInfo, size_t, Array*) arraysetlengthTHook;	
	CFunctionHook!(3, byte[], TypeInfo, size_t, Array*) arraysetlengthiTHook;
}

// ****************************************************************************

void enforce(bool condition, char[] message)
{
	if(!condition)
	{
		//printStackTrace();
		throw new Exception(message);
	}
}

final class DiamondGC : GC
{
	// note: we can't add fields here because we are overwriting the original class's virtual call table
	
	final void mallocHandler(size_t size, void* p)
	{
		//printf("Allocated %d bytes at %08X\n", size, p); printStackTrace();
		version(MEMLOG) synchronized(logsync)
			if(p)
			{
				logDword(PACKET_MALLOC);
				logDword(time(null));
				logStackTrace();
				logDword(p);
				logDword(size);			
			}
		version(MEMLOG_VERBOSE) logMemoryDump(true);
	}

	final void callocHandler(size_t size, void* p)
	{
		//printf("Allocated %d initialized bytes at %08X\n", size, p); printStackTrace();
		version(MEMLOG) synchronized(logsync)
			if(p)
			{
				logDword(PACKET_CALLOC);
				logDword(time(null));
				logStackTrace();
				logDword(p);			
				logDword(size);			
			}
		version(MEMLOG_VERBOSE) logMemoryDump(true);
	}

	final void reallocHandler(size_t size, void* p1, void* p2)
	{
		//printf("Reallocated %d bytes from %08X to %08X\n", size, p1, p2); printStackTrace();
		version(MEMLOG) synchronized(logsync)
			if(p2)
			{
				logDword(PACKET_REALLOC);
				logDword(time(null));
				logStackTrace();
				logDword(p1);
				logDword(p2);
				logDword(size);			
			}
		version(MEMLOG_VERBOSE) logMemoryDump(true);
	}

	override size_t extend(void* p, size_t minsize, size_t maxsize) 
	{
		auto result = super.extend(p, minsize, maxsize); 
		version(MEMLOG) synchronized(logsync)
			if(result)
			{
				logDword(PACKET_EXTEND);
				logDword(time(null));
				logStackTrace();
				logDword(p);
				logDword(result);
			}
		version(MEMLOG_VERBOSE) logMemoryDump(true);
		return result;
	}

	override void free(void *p) 
	{ 
		version(FREECHECK)
		{
			Pool* pool = gcx.findPool(p);
			enforce(pool !is null, "Freed item is not in a pool");

			uint pagenum = (p - pool.baseAddr) / PAGESIZE;
			Bins bin = cast(Bins)pool.pagetable[pagenum];
			enforce(bin <= B_PAGE, "Freed item is not in an allocated page");
			
			size_t size = binsize[bin];
			enforce((cast(size_t)p & (size - 1)) == 0, "Freed item is not aligned to bin boundary");

			if (bin < B_PAGE)  // Check that p is not on a free list
				for (List *list = gcx.bucket[bin]; list; list = list.next)
					enforce(cast(void *)list != p, "Freed item is on a free list");
		}
		version(MEMLOG) synchronized(logsync)
		{
			logDword(PACKET_FREE);
			logDword(time(null));
			logStackTrace();
			logDword(p);
		}
		version(MEMLOG_VERBOSE) logMemoryDump(true);
		version(MEMSTOMP)
		{
			auto c = capacity(p);
			super.free(p);
			if(c>4)
				(cast(ubyte*)p)[4..c] = 0xBD;
		}
		else
			super.free(p); 
		version(MEMLOG_VERBOSE) logMemoryDump(true);
	}

	version(Tango)
	{
		override void *malloc(size_t size, uint bits) { version(MEMLOG_VERBOSE) logMemoryDump(true); auto result = super.malloc(size, bits); mallocHandler(size, result); return result; }
		override void *calloc(size_t size, uint bits) { version(MEMLOG_VERBOSE) logMemoryDump(true); auto result = super.calloc(size, bits); callocHandler(size, result); return result; }
		override void *realloc(void *p, size_t size, uint bits) { version(MEMLOG_VERBOSE) logMemoryDump(true); auto result = super.realloc(p, size, bits); reallocHandler(size, p, result); return result; }
		alias sizeOf capacity;
	}
	else
	{
		override void *malloc(size_t size) { version(MEMLOG_VERBOSE) logMemoryDump(true); auto result = super.malloc(size); mallocHandler(size, result); return result; }
		override void *calloc(size_t size, size_t n) { version(MEMLOG_VERBOSE) logMemoryDump(true); auto result = super.calloc(size, n); callocHandler(size*n, result); return result; }
		override void *realloc(void *p, size_t size) { version(MEMLOG_VERBOSE) logMemoryDump(true); auto result = super.realloc(p, size); reallocHandler(size, p, result); return result; }
	}
}

version(MEMLOG)
{
	extern(C) public void logMemoryDump(bool dataDump, Gcx* gcx = null)
	{
		synchronized(logsync)
		{
			//dataDump ? printf("Dumping memory contents...\n") : printf("Dumping memory map...\n");
			if(gcx is null) gcx = (cast(GC)gc).gcx;
			logDword(dataDump ? PACKET_MEMORY_DUMP : PACKET_MEMORY_MAP);
			logDword(time(null));
			logStackTrace();
			logDword(gcx.npools);
			for(int pn=0;pn<gcx.npools;pn++)
			{
				auto p = gcx.pooltable[pn];
				logDword(p.baseAddr);
				logDword(p.npages);
				logDword(p.ncommitted);
				logData(p.pagetable[0..p.npages]);
				logBits(p.freebits);
				logBits(p.finals);
				logBits(p.noscan);
				if(dataDump)
					logData(p.baseAddr[0..p.ncommitted*PAGESIZE]);
			}
			if(dataDump)
				logData(gcx.bucket);
			//printf("Done\n");
		}
	}

	extern(C) public void logText(char[] text)
	{
		synchronized(logsync)
		{
			logDword(PACKET_TEXT);
			logDword(time(null));
			logStackTrace();
			logDword(text.length);
			logData(text);
		}
	}

	extern(C) public void logNumber(uint n)
	{
		char[24] buf;
		sprintf(buf.ptr, "%08X (%d)", n, n);
		for(int i=12;i<buf.length;i++)
			if(!buf[i])
				return logText(buf[0..i]);
	}
}

size_t fullcollectHandler(void* stackTop, Gcx* gcx)
{
	//printf("minaddr=%08X maxaddr=%08X\n", gcx.minAddr, gcx.maxAddr);	
	//printf("Beginning garbage collection\n");	
	version(MEMLOG) logMemoryDump(true, gcx);
	fullcollectHook.unhook();
	auto result = gcx.fullcollect(stackTop);
	fullcollectHook.hook();
	version(MEMLOG) logMemoryDump(false, gcx);
	//printf("Garbage collection done, %d pages freed\n", result);
	return result;
}

version(MEMSTOMP)
{
	// stomp on shrunk arrays
	 
	extern(C) extern byte[] _d_arraysetlengthT(TypeInfo ti, size_t newlength, Array *p);
	extern(C) extern byte[] _d_arraysetlengthiT(TypeInfo ti, size_t newlength, Array *p);

	extern(C) byte[] arraysetlengthTHandler(TypeInfo ti, size_t newlength, Array *p)
	{
		Array old = *p;
		arraysetlengthTHook.unhook();
		auto result = _d_arraysetlengthT(ti, newlength, p);
		arraysetlengthTHook.hook();
		//printf("_d_arraysetlengthT: %d => %d\n", oldlength, p.length);
		size_t sizeelem = ti.next.tsize();
		if(old.data == p.data && p.length < old.length)
			(cast(ubyte*)p.data)[p.length*sizeelem .. old.length*sizeelem] = 0xBD;
		return result;
	}

	extern(C) byte[] arraysetlengthiTHandler(TypeInfo ti, size_t newlength, Array *p)
	{
		Array old = *p;
		arraysetlengthiTHook.unhook();
		auto result = _d_arraysetlengthiT(ti, newlength, p);
		arraysetlengthiTHook.hook();
		//printf("_d_arraysetlengthiT: %d => %d\n", oldlength, p.length);
		size_t sizeelem = ti.next.tsize();
		if(old.data == p.data && p.length < old.length)
			(cast(ubyte*)p.data)[p.length*sizeelem .. old.length*sizeelem] = 0xBD;
		return result;
	}
}

// ****************************************************************************

static this()
{
	version(MEMLOG) logsync = new Object;
	// replace the garbage collector Vtable
	*cast(void**)gc = DiamondGC.classinfo.vtbl.ptr;

	fullcollectHook.initialize(&Gcx.fullcollect, &fullcollectHandler);
	version(MEMSTOMP)
	{
		arraysetlengthTHook.initialize(&_d_arraysetlengthT, &arraysetlengthTHandler);		
		arraysetlengthiTHook.initialize(&_d_arraysetlengthiT, &arraysetlengthiTHandler);
	}
	version(MEMLOG)
	{
		time_t t = time(null);
		tm *tm = localtime(&t);
		char[256] name;
		sprintf(name.ptr, "%sdiamond_%d-%02d-%02d_%02d.%02d.%02d.mem", LOGDIR.ptr, 1900+tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
		log = fopen(name.ptr, "wb");
	}
}

static ~this()
{
	version(MEMLOG) 
	{
		//printf("Closing memory log...\n");
		fclose(log);
	}
}
