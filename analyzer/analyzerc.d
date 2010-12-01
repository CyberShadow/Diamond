module analyzerc;

import std.stdio;
import std.string;
import std.conv;
import std.file;
import std.path;
import std.date : d_time;
import std.c.time;
import logreader;
import mapfile;
import analysis;

string[PACKET_MAX] eventNames = ["PACKET_MALLOC", "PACKET_CALLOC", "PACKET_REALLOC", "PACKET_EXTEND", "PACKET_FREE", "PACKET_MEMORY_DUMP", "PACKET_MEMORY_MAP", "PACKET_TEXT", "PACKET_NEWCLASS"];
string[PACKET_MAX] shortEventNames = ["MALLOC", "CALLOC", "REALLOC", "EXTEND", "FREE", "MEMDUMP", "MEMMAP", "TEXT", "NCLASS"];
char  [PACKET_MAX] eventChars = "mcrxfDMtC";

char  [B_MAX] pageChars = "45678901P+.x";

int main(string[] argv)
{
	writefln("Diamond Memory Log Analyzer, v0.2");
	writefln("by Vladimir \"CyberShadow\" Panteleev, 2008-2010");
	writefln();
	
	void progressCallback(ulong pos, ulong max)
	{
		writef("%d%%\r", pos*100/max);
		fflush(stdout);
	}
	
	string fileName;
	string mapFileName;
	uint limit = uint.max;
	for (int i=1; i<argv.length; i++)
	{
		string arg = argv[i];
		if (arg=="--limit")
			limit = toUint(argv[++i]);
		else
		if (getExt(arg)=="mem")
			fileName = arg;
		else	
		if (getExt(arg)=="map")
			mapFileName = arg;
		else
		if (getExt(arg))
			writefln("Don't know what to do with .%s files.", getExt(arg));
		else
			writefln("Unknown command-line option: %s", arg);
	}

	if (fileName is null)
	{
		fileName = findMostRecent("*.mem");
		if (fileName is null)
		{
			writefln("There are no .mem files in the current directory. Specify a memory log file on the command line, or run without parameters to use the most recent file in the current directory.");
			return 1;
		}
		writefln("Using the most recent memory dump file.");
	}
	writefln("Loading %s...", fileName);
	auto log = new LogReader(fileName);
	try
		log.load(&progressCallback, limit);
	catch(Exception e)
		writefln("Error: %s", e.msg);
	if (log.events.length is 0)
		return 1;
	writefln("%d events loaded.", log.events.length);
	
	if (mapFileName is null)
	{
		mapFileName = findMostRecent("*.map");
		if (mapFileName is null)
			writefln("There are no .map files in the current directory and you have not specified one on the command line. Symbols will not be available.");
		else
			writefln("Using the most recent map file.");
	}
	MapFile map;
	if (mapFileName)
	{
		map = new MapFile(mapFileName);
		writefln("%d symbols loaded from %s.", map.symbols.length, mapFileName);
	}

	auto analysis = new Analysis(log);

	// a few utility functions...
	
	int parsePositionSubexpression(string s)
	{
		if (s.length==0)
			throw new Exception("Conversion: empty string");
		if (s[0]=='-' || s[0]=='+') // relative to current event
			s = '@' ~ s;

		int padd = find(s, '-');
		int psub = find(s, '+');
		if (psub>0 || padd>0) // support simple arithmetics
			if (psub<=0 || padd>psub)
				return parsePositionSubexpression(s[0..padd-1]) + parsePositionSubexpression(s[padd+1..$]);
			else
				return parsePositionSubexpression(s[0..psub-1]) - parsePositionSubexpression(s[psub+1..$]);
		if (s=="@" || s=="cursor")
			return analysis.cursor;
		else
		if (s=="$" || s=="end")
			return log.events.length-1;
		else
		if (s=="^" || s=="start")
			return -1;
		else
			return toInt(s);
	}

	int parsePosition(string s)
	{
		int position = parsePositionSubexpression(s);
		if (position >= log.events.length || position<-1)
			throw new Exception("Position is out of range");
		return position;
	}

	void parsePositionRange(string[] args, ref int min, ref int max)
	{
		if (args.length==0)
			min = max = analysis.cursor;
		else
		if (args.length==1)
			min = max = parsePosition(args[0]);
		else
		if (args.length==2)
		{
			min = parsePosition(args[0]);
			max = parsePosition(args[1]);
			if (min<0 || min>max)
				throw new Exception("Invalid range");
		}
		else
			throw new Exception("Too many arguments");
	}

	void parseMemoryRange(string[] args, ref uint min, ref uint max)
	{
		if (args.length==0)
			throw new Exception("Specify a memory address or range");
		else
		if (args.length==1)
			min = max = fromHex(args[0]);
		else
		if (args.length==2)
		{
			min = fromHex(args[0]);
			max = fromHex(args[1]);
			if (min>max)
				throw new Exception("Invalid range");
		}
		else
			throw new Exception("Too many arguments");
	}

	string mapLookUp(uint addr)
	{
		if (map is null)
			return "<no symbols>";
		else
			return map.lookup(addr);
	}
	
	void showEvent(int i)
	{
		auto event = log.events[i];
		writef("%7d @ %s: %-7s", i, timeStr(event.time), shortEventNames[event.type]);
		if (cast(ReallocEvent)event) with (cast(ReallocEvent)event)
		{
			writef(" %08X -> %08X - %08X (%d bytes)", oldp, p, p+size, size);
			if (className)
				writef(" %s", className);
			writefln;
		}
		else
		if (cast(MemoryAllocationEvent)event) with (cast(MemoryAllocationEvent)event)
		{
			writef(" %08X - %08X (%d bytes)", p, p+size, size);
			if (className)
				writef(" %s", className);
			writefln;
		}
		else
		if (cast(FreeEvent)event) with (cast(FreeEvent)event)
			writefln(" %08X", p);
		else
		if (cast(MemoryStateEvent)event) with (cast(MemoryStateEvent)event)
			writefln(" (%6d/%6d/%6d)", allocated, committed, total);
		else
		if (cast(TextEvent)event) with (cast(TextEvent)event)
			writefln(" %s", strip(text));
		else
			writefln();
	}

	void showInfo(MemoryStateEvent event, uint p, Pool* pool=null, int rootIndex = -1, uint value=0)
	{
		if (pool is null && rootIndex==-1)
		{
			foreach (ref epool;event.pools)
				if (p >= epool.addr && p < epool.topAddr)
					{ pool = &epool; break; }
			if (pool is null)
				foreach (i, ref root; event.roots)
					if (p >= root.bottom && p < root.top)
						rootIndex = i;
		}
		writef("%08X", p);
		if (value)
			writef(" -> %08X", value);
		if (pool)
		{
			uint pageNr = (p-pool.addr)/PAGESIZE;
			assert(pageNr < pool.npages);
			auto bin = pool.pagetable[pageNr];
			writef(" - %s", pageNames[bin]);
			Node* n = analysis.findNode(p);
			int biti = -1;
			if (n)
			{
				writef(", event #%d (%08X - %08X)", n.eventID, n.p, n.p+analysis.getNodeSize(n));
				biti = (n.p-pool.addr)/16;
			}
			else
			{
				writef(", not allocated");
				if (bin == B_PAGEPLUS)
				{
					while (pool.pagetable[pageNr]==B_PAGEPLUS)
						pageNr--;
					biti = pageNr*PAGESIZE/16;
				}
				else
				if (bin <= B_PAGE)
				{
					uint startAddr = p & ~(pageSizes[bin]-1);
					biti = (startAddr-pool.addr)/16;
				}
			}
			if (biti>=0)
			{
				if (Pool.readBit(pool.noscan, biti))
					writef(", NOSCAN");
				if (pool.finals.length && Pool.readBit(pool.finals, biti))
					writef(", FINALS");
				if (Pool.readBit(pool.freebits, biti))
					writef(", FREE");
			}
		}
		else
		if (rootIndex >= 0)
			writef(" - in root range %08X - %08X", event.roots[rootIndex].bottom, event.roots[rootIndex].top);
		else
		if (p >= event.stackTop && p < event.stackBottom)
		{
			auto dataEvent = cast(MemoryDumpEvent)event;
			if (dataEvent)
			{
				uint f, n=dataEvent.ebp, s=0;
				while (n>s && n<event.stackBottom)
				{
					if (n > p)
					{
						f = s ? dataEvent.readDword(s+4) : 0;
						break;
					}
					s = n;
					n = dataEvent.readDword(n);
				}
				if (f)
					writef(" - in stack frame %08X-%08X of %08X - %s", s, n, f, mapLookUp(f));
				else
					writef(" - in stack (can't find frame)");
			}
			else
				writef(" - in stack (no data)");
		}
		else
			writef(" - outside heap/stack");
		writefln();
	}

	void dump(ubyte[] data, uint startAddr)
	{
		foreach (i,v;data)
		{
			if (i%16==0)
				writef("%08X: ", i+startAddr);
			else
			if (i%8==0)
				writef(" ");
			writef("%02X ", v);
			if (i%16==15 || i==data.length-1)
			{	
				for (int l=i%16+1;l<16;l++)
				{
					if (l%8==0)
						writef(" ");
					writef("   ");
				}
				writef("| ");
				foreach (vv;data[i&~15..i+1])
					if (vv==0)
						writef(" ");
					else if (vv<32 || vv>=127)
						writef(".");
					else
						writef(cast(char)vv);
				writefln;
			}
		}
	}

	while (true)
	{
		highVideo();
		if (analysis.cursor<0)
			writef("    \r> ");
		else
			writef("    \r%s%d> ", eventChars[log.events[analysis.cursor].type], analysis.cursor);
		normVideo();
		auto args = split(strip(readln()), " ");
		if (args.length==0) continue;

		bool allRefs;
		
		try
			switch (tolower(args[0]))
			{
				// === General statistics ===
				case "stats": // display event counts
				{
					int[PACKET_MAX] counts;
					foreach (event;log.events)
						counts[event.type]++;
					for (int i=0;i<PACKET_MAX;i++)
						writefln("%-20s: %8d", eventNames[i], counts[i]);
					writefln("%-20s: %8d", "Total", log.events.length);
					break;
				}
				case "allocstats": // display top allocator call stacks
				{
					static ulong[uint[]] stacks;
					foreach (event;log.events)
					{
						auto allocEvent = cast(LogReader.MemoryAllocationEvent)event;
						if (allocEvent is null) 
							continue;
						if (allocEvent.stackTrace in stacks)
							stacks[allocEvent.stackTrace] += allocEvent.size;
						else
							stacks[allocEvent.stackTrace] = allocEvent.size;
					}
					struct Sorter
					{
						uint[] stack;
					
						int opCmp(Sorter* s) 
						{
							ulong my = stacks[stack];
							ulong that = stacks[s.stack];
							return my==that?0:my>that?-1:1;
						}
					}
					Sorter[] sortedStacks = cast(Sorter[])stacks.keys;
					sortedStacks.sort;
					int n = 5;
					if (args.length>1)
						n = toInt(args[1]);
					if (n>sortedStacks.length) 
						n = sortedStacks.length;
					writefln("Top %d allocators by total allocated data:", n);
					foreach (sorter;sortedStacks[0..n])
					{
						writefln("=== %d ===", stacks[sorter.stack]);
						foreach (func;sorter.stack)
							writefln(" %08X  %s", func, mapLookUp(func));
					}
					break;
				}
				// === timeline information ===
				case "dumps": // list memory dump events
					foreach (i,event;log.events)
						if (event.type == PACKET_MEMORY_DUMP)
							showEvent(i);
					break;
				case "maps": // list memory map events
					foreach (i,event;log.events)
						if (event.type == PACKET_MEMORY_MAP)
							showEvent(i);
					break;
				case "events": // display events in event range
				case "event":
				{
					int min, max;
					parsePositionRange(args[1..$], min, max);
					if (min<0)
						throw new Exception("Invalid position or range");
					for (int i=min;i<=max;i++)
						showEvent(i);
					break;
				}
				case "text":
				{
					string s = std.string.join(args[1..$], " ");
					foreach (i,event;log.events)
						if (event.type == PACKET_TEXT)
						{
							auto textEvent = cast(TextEvent)event;
							if (s.length && textEvent.text.find(s)<0)
								continue;
							showEvent(i);
						}
					break;
				}
				// === navigation ===
				case "g": // set cursor at a certain event number
				case "goto":
				{
					if (args.length!=2)
						throw new Exception("Specify an event number or expression.");
					analysis.goTo(parsePosition(args[1]), &progressCallback);
					break;
				}
				case "n": // next event
				case "next":
					analysis.goTo(analysis.cursor+1);
					break;
				case "p": // previous event
				case "prev":
					analysis.goTo(analysis.cursor-1, &progressCallback);
					break;
				case "nextdump":
					for (int i=analysis.cursor+1;i<log.events.length;i++)
						if (log.events[i].type==PACKET_MEMORY_DUMP)
							{ analysis.goTo(i, &progressCallback); goto Lbreak; }
					throw new Exception("Not found");
				case "nextmap":
					for (int i=analysis.cursor+1;i<log.events.length;i++)
						if (log.events[i].type==PACKET_MEMORY_MAP)
							{ analysis.goTo(i, &progressCallback); goto Lbreak; }
					throw new Exception("Not found");
				case "prevdump":
					for (int i=analysis.cursor-1;i>=0;i--)
						if (log.events[i].type==PACKET_MEMORY_DUMP)
							{ analysis.goTo(i, &progressCallback); goto Lbreak; }
					throw new Exception("Not found");
				case "prevmap":
					for (int i=analysis.cursor-1;i>=0;i--)
						if (log.events[i].type==PACKET_MEMORY_MAP)
							{ analysis.goTo(i, &progressCallback); goto Lbreak; }
					throw new Exception("Not found");
				case "lastdump":
					for (int i=log.events.length-1;i>=0;i--)
						if (log.events[i].type==PACKET_MEMORY_DUMP)
							{ analysis.goTo(i, &progressCallback); goto Lbreak; }
					throw new Exception("Not found");
				case "lastmap":
					for (int i=log.events.length-1;i>=0;i--)
						if (log.events[i].type==PACKET_MEMORY_MAP)
							{ analysis.goTo(i, &progressCallback); goto Lbreak; }
					throw new Exception("Not found");
Lbreak:
					break;
				// === address search and cross-references ===
				case "eventsat": // display last event(s) affecting an address/range
				case "eventat":
				{
					if (analysis.cursor<0)
						throw new Exception("No data (use 'goto' to seek to an event)");
					uint min, max;
					parseMemoryRange(args[1..$], min, max);

					auto n = analysis.findNodeFuzzy(min);
					//auto event = cast(MemoryAllocationEvent)log.events[n.eventID];
					if (n is null) throw new Exception("Address out of range or points to unallocated region");
					//writefln("findNode returned: p=%08X, next.p=%08X", n.p, n.next.p);
					for (;n && n.p+analysis.getNodeSize(n)<=min;n=n.next) {}
					int count;
					for (; n && n.p <= max; n=n.next)
						showEvent(n.eventID), count++;
					if (count==0)
						writefln("No events at address/range.");
					break;
				}
				case "alleventsat": // display all events affecting an address/range
				{
					uint min, max;
					parseMemoryRange(args[1..$], min, max);
					foreach (i,event;log.events)
					{
						uint p1, p2;
						if (cast(MemoryAllocationEvent)event) with (cast(MemoryAllocationEvent)event)
							p1 = p, p2 = p + size;
						else
						if (cast(FreeEvent)event) with (cast(FreeEvent)event)
							p1 = p, p2 = p;
						else
							continue;
						if ((p2 >= min) && (p1 <= max))
							showEvent(i);
					}
					break;
				}
				// === inspection of specific event ===
				case "stack": // display stack of current/specified event
				{
					int event;
					if (args.length==1)
						event = analysis.cursor;
					else
						event = toInt(args[1]);
					foreach (func;log.events[event].stackTrace)
						writefln(" %08X  %s", func, mapLookUp(func));
					break;
				}
				// === inspection of map/dump events ===
				case "info": // display information about a specified address
				{
					if (analysis.cursor<0)
						throw new Exception("No data (use 'goto' to seek to an event)");
					if (args.length!=2)
						throw new Exception("Specify an address");
					uint address = fromHex(args[1]);
					auto event = cast(MemoryStateEvent)log.events[analysis.cursor];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					showInfo(event, address);
					break;
				}
				case "pools": // display memory pools
				{
					int eventID;
					if (args.length==1)
						eventID = analysis.cursor;
					else
						eventID = toInt(args[1]);
					auto event = cast(MemoryStateEvent)log.events[eventID];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					foreach (ref pool;event.pools)
						writefln("%08X - %08X, %4d/%4d/%4d pages", pool.addr, pool.topAddr, pool.npages-pool.nfree, pool.ncommitted, pool.npages);
					break;
				}
				case "map": // display a memory map
				{
					int eventID = analysis.cursor;
					uint address = 0;
					if (args.length>1)
					{
						if (args[1]!="*")
							address = fromHex(args[$-1]);
						if (args.length>2)
							eventID = toInt(args[2]);
					}
					if (eventID<0)
						throw new Exception("No data (specify or goto event)");
					auto event = cast(MemoryStateEvent)log.events[eventID];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					bool found;
					int columns = (getWidth() - 10) / 17;
					if (columns > 16) columns = 16;
					foreach (ref pool;event.pools)
						if (address==0 || (address >= pool.addr && address < pool.topAddr))
						{
							writefln("Page map for pool %08X - %08X (%4d/%4d/%4d pages):", pool.addr, pool.topAddr, pool.npages-pool.nfree, pool.ncommitted, pool.npages);
							writef("(page size = 0x1000)      ");
							for (int i=1;i<columns;i++)
								writef("      +%X0000     ", i);
							foreach (pageNr,bin;pool.pagetable)
							{
								auto addr = pool.addr + pageNr*PAGESIZE;
								if (pageNr%16==0)
									if (pageNr/16%columns==0)
									{
										writefln;
										writef("%08X: ", addr);
									}
									else
										writef(' ');
								bool hasScan, hasNoScan;
								// does this page have pointers?
								if (bin<=B_PAGEPLUS)
								{
									uint start, step;
									if (bin==B_PAGEPLUS)
									{
										start = pageNr;
										while (pool.pagetable[start]==B_PAGEPLUS)
											start--;
										start = start*PAGESIZE/16;
										step = PAGESIZE/16;
									}
									else
									{
										start = pageNr*PAGESIZE/16;
										step = pageSizes[bin]/16;
									}
									for (uint biti=start;biti<start+PAGESIZE/16;biti+=step)
										if (Pool.readBit(pool.noscan, biti))
											hasNoScan = true;
										else
											hasScan = true;
								}
								else
									hasNoScan = true;
								if (hasScan && !hasNoScan)
									highVideo();
								else
								if (!hasScan && hasNoScan)
									lowVideo();
								writef(pageChars[bin]);
								if (hasScan != hasNoScan)
									normVideo();
							}
							writefln();
							found = true;
						}
					if (!found)
						throw new Exception("Specified address does not belong in any pool.");
					break;
				}
				case "binmap": // display a map of the specified memory page
				{
					if (args.length<2)
						throw new Exception("Specify an address");
					uint address = fromHex(args[1]);
					int eventID = analysis.cursor;
					if (args.length>2)
						eventID = toInt(args[2]);
					if (eventID<0)
						throw new Exception("No data (specify or goto event)");
					auto event = cast(MemoryStateEvent)log.events[eventID];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					Pool* pool;
					foreach (ref epool;event.pools)
						if (address >= epool.addr && address < epool.topAddr)
							{ pool = &epool; break; }
					if (pool is null)
						throw new Exception("Specified address does not belong in any pool.");
					uint pageNr = (address-pool.addr) / PAGESIZE;
					auto bin = pool.pagetable[pageNr];
					if (bin >= B_PAGE)
						throw new Exception("This page is not a bin page.");
					auto binsize = pageSizes[bin];
					auto objectCount = PAGESIZE / binsize;
					auto step = binsize/16;

					int columns = 4;
					if (objectCount/16 < 4)
						columns = objectCount/16;
					writefln("Bin map for page %08X - %08X:", pool.addr + pageNr*PAGESIZE, pool.addr + (pageNr+1)*PAGESIZE);
					writef("(object size = 0x%03X)     ", binsize);
					for (int i=1;i<columns;i++)
						writef("       +%03X      ", i*16*binsize);
					for (uint i=0;i<objectCount;i++)
					{
						uint biti = (PAGESIZE/16)*pageNr + i*step;
						auto addr = pool.addr + pageNr*PAGESIZE + i*binsize;
						if (i%16==0)
							if (i/16%columns==0)
							{
								writefln;
								writef("%08X: ", addr);
							}
							else
								writef(' ');
						bool free   = Pool.readBit(pool.freebits, biti);
						bool noscan = Pool.readBit(pool.noscan  , biti);
						bool finals = Pool.readBit(pool.finals  , biti);
						if (free)
							writef('.');
						else
						{
							if (noscan)
								lowVideo();
							else
								highVideo();
							writef(finals ? 'C' : 'D');
							normVideo();
						}
					}
					writefln();
					break;
				}
				case "stackinfo":
				{
					int eventID;
					if (args.length==1)
						eventID = analysis.cursor;
					else
						eventID = toInt(args[1]);
					auto event = cast(MemoryStateEvent)log.events[eventID];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					writefln("ESP    = %08X (stack top)", event.stackTop);
					writefln("EBP    = %08X", event.ebp);
					writefln("bottom = %08X", event.stackBottom);
					break;
				}
				case "roots":
				{
					int eventID;
					if (args.length==1)
						eventID = analysis.cursor;
					else
						eventID = toInt(args[1]);
					auto event = cast(MemoryStateEvent)log.events[eventID];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					foreach (ref root; event.roots)
						writefln("%08X - %08X (%d bytes)", root.bottom, root.top, root.top - root.bottom);
					break;
				}
				case "allrefs": // search for all references to address/range
					allRefs = true;
					goto Lroots;
				case "refs": // search for all references to address/range
					allRefs = false;
					goto Lroots;
				Lroots:
				{
					if (analysis.cursor<0)
						throw new Exception("No data (use 'goto' to seek to an event)");
					uint min, max;
					if (args.length==1)
						throw new Exception("Specify a memory address or range");
					else
					if (args.length==2)
						min = max = fromHex(args[1]);
					else
						min = fromHex(args[1]), max = fromHex(args[2]);
					auto event = cast(MemoryStateEvent)log.events[analysis.cursor];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					auto dataEvent = cast(MemoryDumpEvent)log.events[analysis.cursor];
					if (dataEvent is null && analysis.cursor>0) dataEvent = cast(MemoryDumpEvent)log.events[analysis.cursor-1];
					if (dataEvent is null) throw new Exception("This is not a memory dump event, or not directly following one.");
					int lastEvent, count;
					foreach (int poolNr,ref pool;event.pools)
						for (int pageNr=0;pageNr<pool.ncommitted;pageNr++)
						{
							uint[] data = cast(uint[])dataEvent.loadPageData(poolNr, pageNr);
							foreach (i,v;data)
								if (min <= v && v < max)
								{
									uint address = pool.addr + pageNr*PAGESIZE + i*uint.sizeof;
									if (!allRefs) // check if the reference is from something the GC would scan, unless the user wants to see all references
									{
										auto bin = pool.pagetable[pageNr];
										if (bin >= B_FREE)
											continue;
										uint biti;
										if (bin == B_PAGEPLUS)
										{
											int p = pageNr;
											while (pool.pagetable[p]==B_PAGEPLUS)
												p--;
											biti = p*PAGESIZE/16;
										}
										else
										{
											uint startAddr = address & ~(pageSizes[bin]-1);
											biti = (startAddr-pool.addr)/16;
										}
										//writefln("address=%08X, page=%s, startAddr => %08X", address, pageNames[bin], startAddr);
										if (bin < B_PAGE && Pool.readBit(pool.freebits, biti))
											continue;
										if (Pool.readBit(pool.noscan, biti))
											continue;
									}

									Node* n = analysis.findNode(address);
									auto eventID = n is null ? 0 : n.eventID;
									if (eventID != lastEvent)
									{
										if (lastEvent && count>10)
											writefln("... and %d more from event #%d", count-10, lastEvent);
										count = 0;
										lastEvent = eventID;
									}
									count++;
									if (eventID==0 || count<=10)
										showInfo(dataEvent, address, &pool, -1, v);
								}
							delete data;
						}

					uint[] data = cast(uint[])dataEvent.loadStackData();
					foreach (i,v;data)
						if (min <= v && v < max)
							showInfo(dataEvent, dataEvent.stackTop + i*uint.sizeof, null, -1, v);
					delete data;

					foreach (rootIndex, ref root; dataEvent.roots)
						if (root.top - root.bottom != 0)
						{
							data = cast(uint[])dataEvent.loadRootData(root);
							foreach (i,v;data)
								if (min <= v && v < max)
									showInfo(dataEvent, root.bottom + i*uint.sizeof, null, rootIndex, v);
							delete data;
						}

					if (lastEvent && count>10)
						writefln("... and %d more from event #%d", count-10, lastEvent);
					break;
				}
				case "trace":
				{
					if (analysis.cursor<0)
						throw new Exception("No data (use 'goto' to seek to an event)");
					if (args.length==1)
						throw new Exception("Specify a memory address");
					uint p = fromHex(args[1]);
					auto n = analysis.findNode(p);
					if (n is null) throw new Exception("Address out of range or points to unallocated region");

					auto event = cast(MemoryStateEvent)log.events[analysis.cursor];
					if (event is null) throw new Exception("This is not a memory dump/map event.");
					auto dataEvent = cast(MemoryDumpEvent)log.events[analysis.cursor];
					if (dataEvent is null && analysis.cursor>0) dataEvent = cast(MemoryDumpEvent)log.events[analysis.cursor-1];
					if (dataEvent is null) throw new Exception("This is not a memory dump event, or not directly following one.");

					n = analysis.trace(n, event, dataEvent);
					while (n)
					{
						if (n.p && n.eventID)
							showEvent(n.eventID);
						if (n.trace.next)
							writefln("\t%08X -> %08X", n.trace.from, n.trace.to);
						n = n.trace.next;
					}
					break;
				}
				case "dump": // dump memory
				{
					if (analysis.cursor<0)
						throw new Exception("No data (use 'goto' to seek to an event)");
					uint min, max;
					if (args.length==1)
						throw new Exception("Specify a memory address or range");
					else
					if (args.length==2)
					{
						min = fromHex(args[1]);
						auto n = analysis.findNode(min);
						if (n && n.p==min)
						{
							max = min + analysis.getNodeSize(n);
							if (max-min > 0x200)
								max = min + 0x200;
						}
						else
							max = min + 0x100;
					}
					else
						min = fromHex(args[1]), max = fromHex(args[2]);
					auto event = cast(MemoryDumpEvent)log.events[analysis.cursor];
					if (event is null && analysis.cursor>0) event = cast(MemoryDumpEvent)log.events[analysis.cursor-1];
					if (event is null) throw new Exception("This is not a memory dump event.");
					bool found;
					foreach (int poolNr, ref pool;event.pools)
						if (pool.addr<=min && pool.topAddr>=max)
						{
							if (max>pool.topCommittedAddr) throw new Exception("Specified address range intersects a reserved memory region");
							found = true;
							ubyte[] data = event.loadPoolData(poolNr);
							dump(data[min-pool.addr .. max-pool.addr], min);
							delete data;
						}
					if (!found)
						if (event.stackTop<=min && event.stackBottom>=max)
						{
							found = true;
							ubyte[] data = event.loadStackData();
							dump(data[min-event.stackTop .. max-event.stackTop], min);
							delete data;
						}
					if (!found)
						foreach (ref root; event.roots)
							if (root.bottom<=min && root.top>=max)
							{
								found = true;
								ubyte[] data = event.loadRootData(root);
								dump(data[min-root.bottom.. max-root.bottom], min);
								delete data;
							}
					if (!found)
						throw new Exception("Data for specified address range is not available.");
					break;
				}
				// === symbols ===
				case "symbol":
				case "symbols":
				{
					if (args.length!=2)
						throw new Exception("Specify a search pattern");
					foreach (ref symbol; map.symbols)
						if (symbol.name.find(args[1])>=0)
							writefln("%08X - %s", symbol.address, symbol.prettyName());
					break;
				}
				case "symbolat":
				{
					if (args.length!=2)
						throw new Exception("Specify an address");
					uint address = fromHex(args[1]);
					writefln("%08X - %s", address, mapLookUp(address));
					break;
				}
				// === history editing ===
				case "swap":
				{
					if (args.length!=3)
						throw new Exception("Specify two events");
					uint e1 = toInt(args[1]);
					uint e2 = toInt(args[2]);
					auto e = log.events[e1]; log.events[e1] = log.events[e2]; log.events[e2] = e;
					break;
				}
				case "fixgcallocs": // fix allocations during GCs in history
				{
					int d = -1;
					for (int i=0; i<log.events.length; i++)
					{
						auto e = log.events[i];
						if (e.type == PACKET_MEMORY_DUMP)
							if (d != -1)
								throw new Exception("Double DUMP event");
							else
								d = i;
						else
						if (e.type == PACKET_MEMORY_MAP)
							if (d == -1)
								throw new Exception("MAP event with no DUMP event");
							else
							{
								if (d+1 < i)
								{
									writefln("%d - %d", d+1, i-1);
									insert(log.events, d+1, e);
									i++;
								}
								d = -1;
							}
					}
					break;
				}
				// === diagnostics ===
				case "integrity": // verify the validity of the analysis state
				{
					int count = 0;
					for (auto n = analysis.first;n;n=n.next)
					{
						count++;
						enforce(n.prev is null ? n is analysis.first : n is n.prev.next, "Broken chain");
						enforce(n.next is null ? n is analysis.last  : n is n.next.prev, "Broken chain");
						auto event = cast(MemoryAllocationEvent)log.events[n.eventID];
						enforce(event !is null, "Invalid event");
						enforce(n.p == event.p, "Node/Event pointer mismatch");
						if (n.next) enforce(n.p+event.size <= n.next.p, "Node continuity broken");
						if (n.prev && ((n.prev.p+analysis.getNodeSize(n.prev))>>16) < (n.p>>16)) lazyEnforce(analysis.map[n.p>>16] is n, format("Node is not mapped (event %d)", n.eventID)); // BUG: this check should be stricter
					}
					writefln("%d nodes checked.", count);
					foreach (seg,n;analysis.map)
						if (n)
						{
							if (n.prev)
								enforce(n.prev.p>>16 < seg, "Mapped node is not first");
							if (n.p>>16 < seg) // stretches across segs
								enforce(n.next is null || (n.next.p>>16) >= seg, "Mismapped node");
							else
								enforce(n.p>>16 == seg, "Mismapped node");
						}
					writefln("Map checked.");
					break;
				}
				case "freecheck": // enable/disable free list checking
					analysis.freeCheck = !analysis.freeCheck;
					writefln("Free node verification is %s.", analysis.freeCheck?"ON":"OFF");
					break;
				// other
				case "help":
				case "?":
					writefln("Command list. Event numbers are always in decimal, addresses are in hex.");
					writefln("Use ^ in event numbers for start, @ for cursor position, $ for end of file.");
					writefln("Please consult the documentation for details on specific commands.");
					/*highVideo();*/writefln("=== general statistics ===");/*normVideo();*/
					writefln("stats                              display event counts");
					writefln("allocstats                         display top allocator call stacks");
					/*highVideo();*/writefln("=== timeline information ===");/*normVideo();*/
					writefln("dumps                              list memory dump events");
					writefln("maps                               list memory map events");
					writefln("events <event> [<event2>]          display events in event range");
					writefln("text [<string>]                    display text events containing string");
					/*highVideo();*/writefln("=== navigation ===");/*normVideo();*/
					writefln("g[oto] <event>                     set cursor at a certain event number");
					writefln("n[ext]                             next event");
					writefln("p[rev]                             previous event");
					writefln("nextdump                           next dump event");
					writefln("nextmap                            next map event");
					writefln("prevdump                           previous dump event");
					writefln("prevmap                            previous map event");
					writefln("lastdump                           last dump event");
					writefln("lastmap                            last map event");
					/*highVideo();*/writefln("=== address search and cross-references ===");/*normVideo();*/
					writefln("eventat <address> [<address2>]     show last event affecting an address/range");
					writefln("alleventsat <address> [<address2>] show all events affecting an address/range");
					/*highVideo();*/writefln("=== inspection of specific event ===");/*normVideo();*/
					writefln("stack [<event>]                    show stack of current/specified event");
					/*highVideo();*/writefln("=== inspection of map/dump events ===");/*normVideo();*/
					writefln("info <address>                     show information about a specified address");
					writefln("pools [<event>]                    display memory pools");
					writefln("map [<address>|* [<event>]]        display a memory map");
					writefln("binmap <address> [<event>]         display a map of the specified memory page");
					writefln("stackinfo [<event>]                display stack information");
					writefln("roots [<event>]                    display root ranges");
					writefln("refs <address> [<address2>]        search for all references to address/range");
					writefln("allrefs <address> [<address2>]     same, but also search unallocated memory");
					writefln("dump <address> [<address2>]        dump memory at address/range");
					/*highVideo();*/writefln("=== symbols ===");/*normVideo();*/
					writefln("symbol <symbol>                    show symbols matching name");
					writefln("symbolat <address>                 look up symbol by offset");
					/*highVideo();*/writefln("=== diagnostics ===");/*normVideo();*/
					writefln("integrity                          verify the validity of the analysis state");
					writefln("freecheck                          enable/disable free list checking");
					break;
				case "exit":
				case "quit":
				case "q":
					return 0;
				default:
					writefln("Unknown command.");
					break;
			}
		catch(Exception e)
			writefln("Error: %s", e.msg);
	}
	assert(0);
}

uint fromHex(string s)
{
	uint result;
	if (!sscanf(toStringz(s), "%x", &result))
		throw new Exception(format("%s is not a valid hex integer", s));
	return result;
}

string timeStr(time_t time)
{
	char[12] s;
	strftime(s.ptr, s.length, "%H:%M:%S", localtime(&time));
	return toString(s.dup.ptr);
}

string findMostRecent(string pattern)
{
	d_time newestTime;
	string newestFile;
	foreach (file;listdir("."))
		if (fnmatch(file, pattern))
		{
			d_time c, a, m;
			getTimes(file, c, a, m);
			if (m > newestTime)
			{
				newestTime = m;
				newestFile = file;
			}
		}
	return newestFile;
}

version(Windows) // use Windows API to set the colour
{
	import std.c.windows.windows;
	extern(Windows) extern HANDLE GetStdHandle(int);

	/// Emphasized text
	void highVideo()
	{
		fflush(stdout);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	}

	/// Darker text
	void lowVideo()
	{
		fflush(stdout);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 8);
	}

	/// Normal text
	void normVideo()
	{
		fflush(stdout);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	}

	/// Get terminal width
	uint getWidth()
	{
		CONSOLE_SCREEN_BUFFER_INFO csbi;

		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
		return csbi.dwSize.X;
	}
}
else
version(linux) // use ANSI escape codes
{
	import std.c.stdlib;
	
	/// Emphasized text
	void highVideo()
	{
		writef("\x1B[1m");
	}

	/// Darker text
	void lowVideo()
	{
		//writef("\x1B[2m"); // low-intensity - not supported by many terminals :(
		writef("\x1B[30;1m");
	}

	/// Normal text
	void normVideo()
	{
		writef("\x1B[m");
	}

	/// Get terminal width
	uint getWidth()
	{
		try
			toUint(toString(getenv("COLUMNS")));
		catch(Object o)
			return 80;
	}
}
else
{
	/// Emphasized text
	void highVideo() { }

	/// Darker text
	void lowVideo() { }

	/// Normal text
	void normVideo() { }

	/// Get terminal width
	uint getWidth() { return 80; }
}

/// Assert, but not just for debug builds
void enforce(bool condition, string message)
{
	if (!condition)
		throw new Exception(message);
}

/// ditto
void lazyEnforce(bool condition, lazy string message)
{
	if (!condition)
		throw new Exception(message);
}

void insert(T)(ref T[] arr, size_t pos, T el)
{
	arr ~= T.init;
	std.c.string.memmove(arr.ptr+pos+1, arr.ptr+pos, T.sizeof * (arr.length - pos));
	arr[pos] = el;
}
