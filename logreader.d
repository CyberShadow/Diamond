module logreader;

import core.stdc.time;

import std.string;
import std.stream;

enum : uint
{
	PACKET_MALLOC,
	PACKET_CALLOC,
	PACKET_REALLOC,
	PACKET_EXTEND,
	PACKET_FREE,
	PACKET_MEMORY_DUMP,
	PACKET_MEMORY_MAP,
	PACKET_TEXT,
	PACKET_NEWCLASS,
	PACKET_MAX
}

enum 
{
	PAGESIZE = 4096
}

enum
{
    B_16,
    B_32,
    B_64,
    B_128,
    B_256,
    B_512,
    B_1024,
    B_2048,
    B_PAGE,             // start of large alloc
    B_PAGEPLUS,         // continuation of large alloc
    B_FREE,             // free page
    B_UNCOMMITTED,      // memory not committed for this page
    B_MAX
}

uint  [B_PAGEPLUS] pageSizes = [ 16,32,64,128,256,512,1024,2048,4096 ];
string[B_MAX] pageNames = ["B_16", "B_32", "B_64", "B_128", "B_256", "B_512", "B_1024", "B_2048", "B_PAGE", "B_PAGEPLUS", "B_FREE", "B_UNCOMMITTED"];

alias void delegate(ulong pos, ulong max) LogProgressDelegate;

const uint FORMAT_VERSION = 4; // format of the log file

final class LogReader
{
	BufferedFile f;
	string fileName;

	this(string fileName)
	{
		this.fileName = fileName;
	}
	
	void load(LogProgressDelegate progressDelegate = null, uint limit=uint.max)
	{
		f = new BufferedFile(fileName);
		if (f is null)
			throw new Exception("Can't open file " ~ fileName);
		ulong fileSize = f.size;

		auto fileVersion = readDword;
		if (fileVersion != FORMAT_VERSION)
			throw new Exception(format("File version mismatch - file is in version %d, while I only understand version %d logs. Please use the same analyzer version as the Diamond version used to record this memory log.", fileVersion, FORMAT_VERSION));
		
		uint n; events.length = 256;
		scope(exit) events.length = n;
		while (!f.eof && n<limit)
		{
			if ((n&0xFF)==0 && progressDelegate)
				progressDelegate(f.position, fileSize);
			uint type = readDword;
			Event event;
			switch (type)
			{
				case PACKET_MALLOC:
					event = new MallocEvent; break;
				case PACKET_CALLOC:
					event = new CallocEvent; break;
				case PACKET_REALLOC:
					event = new ReallocEvent; break;
				case PACKET_EXTEND:
					event = new ExtendEvent; break;
				case PACKET_FREE:
					event = new FreeEvent; break;
				case PACKET_MEMORY_DUMP:
					event = new MemoryDumpEvent; break;
				case PACKET_MEMORY_MAP:
					event = new MemoryMapEvent; break;
				case PACKET_TEXT:
					event = new TextEvent; break;
				case PACKET_NEWCLASS:
					event = new NewClassEvent; break;
				default:
					throw new Exception("Unknown packet type");
			}
			MemoryEvent memoryEvent = cast(MemoryEvent)event;
			if (memoryEvent) // store non-metadata events only
			{
				memoryEvent.type = type;
				if (n>=events.length)
					events.length = events.length*2;
				events[n] = memoryEvent;
				n++;
			}
		}
	}

	uint readDword()
	{
		uint result;
		f.read(result);
		return result;
	}

	ubyte[] readData(uint count)
	{
		ubyte[] result = new ubyte[count];
		f.readExact(result.ptr, result.length);
		return result;
	}

	uint[] readDwords(uint count)
	{
		uint[] result = new uint[count];
		f.readExact(result.ptr, result.length*4);
		return result;
	}

	class Event
	{
		uint type;
	}

	class MemoryEvent : Event
	{
		time_t time;
		uint[] stackTrace;

		this()
		{
			time = readDword();
			while (true)
			{
				uint p = readDword();
				if (!p) break;
				stackTrace ~= p;
			}
		}
	}

	private string newClassName;

	class MemoryAllocationEvent : MemoryEvent
	{
		uint p, size;
		string className;
		this()
		{
			super();
			readExtraPointers();
			p = readDword();
			size = readDword();
			if (newClassName)
			{
				className = newClassName;
				newClassName = null;
			}
		}

		void readExtraPointers() {} // HACK: remove in next file format
	}

	class MallocEvent : MemoryAllocationEvent
	{
	}

	class CallocEvent : MemoryAllocationEvent
	{
	}

	class ReallocEvent : MemoryAllocationEvent  // TODO : reorganize
	{
		uint oldp;

		override void readExtraPointers()
		{
			oldp = readDword();
		}
	}

	class ExtendEvent : MemoryAllocationEvent
	{
		this()
		{
			super();
		}
	}

	class FreeEvent : MemoryEvent
	{
		uint p;

		this()
		{
			super();
			p = readDword();
		}
	}

	struct Pool
	{
		uint addr, npages, ncommitted;
		ubyte[] pagetable;
		uint[] freebits, finals, noscan;
		ulong[] dataOffsets;

		uint topAddr() { return addr + npages*PAGESIZE; }
		uint topCommittedAddr() { return addr + ncommitted*PAGESIZE; }

		uint nfree()
		{
			uint result;
			foreach (p;pagetable)
				if (p==B_FREE || p==B_UNCOMMITTED)
					result++;
			return result;
		}

		static bool readBit(uint[] data, uint i)
		{
			return (data[i >> 5] & (1 << (i & 0x1F))) != 0;
		}
	}

	struct Root
	{
		uint bottom, top;
		ulong dataOffset;
	}
		
	private ulong[][] pageOffsetHistory;

	class MemoryStateEvent : MemoryEvent
	{
		Pool[] pools;
		uint stackTop, stackBottom, ebp;
		ulong stackOffset;
		Root[] roots;

		this(bool data)
		{
			super();
			
			stackTop = readDword();
			stackBottom = readDword();
			ebp = readDword();
			assert(stackTop%4 == 0 && stackBottom%4 == 0);
			if (data)
			{
				stackOffset = f.position;
				f.seekCur(stackBottom - stackTop);
			}
			
			roots.length = readDword();
			foreach (ref root; roots)
			{
				root.bottom = readDword();
				root.top = readDword();
				if (data)
					if (readDword())
					{
						root.dataOffset = f.position;
						f.seekCur(root.top - root.bottom);
					}
			}

			pools.length = readDword();
			if (pageOffsetHistory.length < pools.length)
				pageOffsetHistory.length = pools.length;
			foreach (poolNr, ref pool;pools)
				with (pool)
				{
					addr = readDword;
					npages = readDword;
					ncommitted = readDword;
					if (npages >= 0x100000 || ncommitted >= 0x100000)   // address space / PAGESIZE
						throw new Exception("Too many pages");   // may happen if the memory log is corrupted
					pagetable = readData(npages);
					freebits = readDwords(readDword);
					finals = readDwords(readDword);
					noscan = readDwords(readDword);
					if (data)
					{
						dataOffsets.length = ncommitted;
						if (pageOffsetHistory[poolNr].length < ncommitted)
							pageOffsetHistory[poolNr].length = ncommitted;
						for (int page=0;page<ncommitted;page++)
						{
							auto dataPresent = readDword;
							if (dataPresent)
							{
								dataOffsets[page] = f.position;
								pageOffsetHistory[poolNr][page] = f.position;
								f.seekCur(PAGESIZE);
							}
							else
							{
								ulong offset = pageOffsetHistory[poolNr][page];
								if (offset==0 || offset>f.position)
									throw new Exception("Invalid page data backreference");
								dataOffsets[page] = pageOffsetHistory[poolNr][page];
							}
						}
					}
				}
		}

		final uint allocated()
		{
			uint result;
			foreach (pool;pools)
				result += pool.npages - pool.nfree;
			return result;
		}

		final uint committed()
		{
			uint result;
			foreach (pool;pools)
				result += pool.ncommitted;
			return result;
		}

		final uint total()
		{
			uint result;
			foreach (pool;pools)
				result += pool.npages;
			return result;
		}

		final Pool* findPool(uint addr)
		{
			foreach (int poolNr, ref pool;pools)
				if (pool.addr<=addr && pool.topAddr>addr)
					return &pool;
			return null;
		}
	}
	
	final class MemoryDumpEvent : MemoryStateEvent
	{
		uint[B_MAX] buckets;
		
		this()
		{
			super(true);
			buckets[] = readDwords(B_MAX);
		}

		ubyte[] loadPageData(int poolNr, int pageNr)
		{
			Pool* p = &pools[poolNr];
			f.seekSet(cast(long)p.dataOffsets[pageNr]);
			return readData(PAGESIZE);
		}
		
		ubyte[] loadPoolData(int poolNr)
		{
			Pool* p = &pools[poolNr];
			ubyte[] result;
			result.length = p.ncommitted * PAGESIZE;
			for (int pageNr=0;pageNr<p.ncommitted;pageNr++)
			{
				f.seekSet(cast(long)p.dataOffsets[pageNr]);
				f.readExact(result.ptr+pageNr*PAGESIZE, PAGESIZE);
			}
			return result;
		}

		ubyte[] loadStackData()
		{
			f.seekSet(cast(long)stackOffset);
			return readData(stackBottom - stackTop);
		}

		ubyte[] loadRootData(ref Root root)
		{
			if (!root.dataOffset)
				throw new Exception(format("No data for root area %08X-%08X", root.bottom, root.top));
			f.seekSet(cast(long)root.dataOffset);
			return readData(root.top - root.bottom);
		}

		uint readDword(uint addr)
		{
			if (addr >= stackTop && addr < stackBottom)
			{
				f.seekSet(cast(long)(stackOffset + addr-stackTop));
				return this.outer.readDword();
			}
			auto pool = findPool(addr);
			if (pool)
			{
				if (addr>=pool.topCommittedAddr) throw new Exception(format("Specified memory address %08X is in a reserved memory region", addr));
				f.seekSet(cast(long)(pool.dataOffsets[(addr-pool.addr)/PAGESIZE] + (addr-pool.addr)%PAGESIZE));
				return this.outer.readDword();
			}
			foreach (ref root; roots)
				if (addr >= root.bottom && addr < root.top)
				{
					if (root.dataOffset)
					{
						f.seekSet(cast(long)(root.dataOffset + addr-root.bottom));
						return this.outer.readDword();
					}
					else
						throw new Exception(format("Specified memory address %08X is in a root zone outside the heap, however there is no data for this root area.", addr));
				}

			throw new Exception(format("Specified memory address %08X is at an unknown location", addr));
		}
	}

	final class MemoryMapEvent : MemoryStateEvent
	{
		this()
		{
			super(false);
		}
	}

	final class TextEvent : MemoryEvent
	{
		string text;

		this()
		{
			super();
			text = cast(string)readData(readDword());
		}
	}

	final class NewClassEvent : Event
	{
		string className;
		
		this()
		{
			className = cast(string)readData(readDword());
			newClassName = className;
		}
	}

	MemoryEvent[] events;
}

alias LogReader.MemoryAllocationEvent MemoryAllocationEvent;
alias LogReader.MallocEvent MallocEvent;
alias LogReader.CallocEvent CallocEvent;
alias LogReader.ReallocEvent ReallocEvent;
alias LogReader.ExtendEvent ExtendEvent;
alias LogReader.FreeEvent FreeEvent;
alias LogReader.MemoryStateEvent MemoryStateEvent;
alias LogReader.MemoryDumpEvent MemoryDumpEvent;
alias LogReader.MemoryMapEvent MemoryMapEvent;
alias LogReader.TextEvent TextEvent;
alias LogReader.Pool Pool;
