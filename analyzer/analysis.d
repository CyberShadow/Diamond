module analysis;

import logreader;
import std.string; // diagnostic

alias void delegate(ulong pos, ulong max) GoToProgressDelegate;

final class Analysis
{
	LogReader log;
	int cursor = -1;  /// cursor points to the command we last processed
	Node*[0x10000] map;
	Node* first, last;
	bool freeCheck;   /// check free lists for every memory dump traversed

	this(LogReader log)
	{
		this.log = log;
	}

final:
	void goTo(int position, GoToProgressDelegate progressDelegate = null)
	{
		if (position >= log.events.length || position<-1)
			throw new Exception("Position is out of range");
		if (cursor > position) // go back
			reset();
		int start = cursor;
		while (cursor < position)
		{
			if ((cursor&0xFF)==0 && progressDelegate)
				progressDelegate(cursor-start, position-start);
			cursor++;
			try
				switch (log.events[cursor].type)
				{
					case PACKET_MALLOC:
					case PACKET_CALLOC:
					case PACKET_REALLOC:
					case PACKET_EXTEND:
					{
						auto event = cast(MemoryAllocationEvent)log.events[cursor];
						if (event.type==PACKET_EXTEND || (event.type==PACKET_REALLOC && (cast(ReallocEvent)event).oldp==event.p))
						{
							auto n = findNode(event.p);
							if (n is null) throw new Exception(format("Can't find node to extend at %08X", event.p));
							if (n.p != event.p) throw new Exception(format("Trying to extend node at %08X using address %08X", n.p, event.p));
							unmapNode(event.p, event.size);
							removeNode(n);
						}
						else
						{
							for (auto n = findNodeFuzzy(event.p);n && n.p<event.p+event.size;n=n.next)
								if ((event.p+event.size >= n.p) && (event.p < n.p+getNodeSize(n)))
									throw new Exception(format("Allocated range %08X - %08X is intersecting with node %08X - %08X allocated by %d", event.p, event.p+event.size, n.p, n.p+getNodeSize(n), n.eventID));
						}
						auto n = new Node;
						n.eventID = cursor;
						n.p = event.p;
						addNode(n);
						mapNode(n, event.size);
						break;
					}
					case PACKET_FREE:
					{
						auto event = cast(FreeEvent)log.events[cursor];
						auto n = findNode(event.p);
						if (n is null) throw new Exception(format("Can't find node to free at %08X", event.p));
						try
						{
							if (n.p != event.p) throw new Exception(format("Trying to free node using address %08X", event.p));
							auto oldEvent = cast(MemoryAllocationEvent)log.events[n.eventID];
							unmapNode(event.p, oldEvent.size);
							removeNode(n);
						}
						catch(Exception e)
							throw new Exception(format("Error with freeing node at %08X (allocated by #%d): %s", n.p, n.eventID, e.msg));
						break;
					}
					case PACKET_MEMORY_MAP:
					{
						auto event = cast(MemoryStateEvent)log.events[cursor];

						MemoryStateEvent prevEvent = null;
						foreach_reverse(e; log.events[0..cursor])
							if (e.type == PACKET_MEMORY_DUMP)
							{
								prevEvent = cast(MemoryStateEvent)e;
								break;
							}
						if (prevEvent is null) throw new Exception("No corresponding dump event for map event");

						int poolNr = 0;
						Pool* pool = &event.pools[poolNr];
						Node*[] freeNodes;
						for (auto n=first;n;n=n.next)
							try
							{
								while (n.p >= pool.topAddr)
									poolNr++, pool = &event.pools[poolNr];
								Pool* prevPool = &prevEvent.pools[poolNr];
								if (n.p < pool.addr) throw new Exception("Node isn't in any pools");
								auto oldEvent = cast(MemoryAllocationEvent)log.events[n.eventID];
								assert(n.p == oldEvent.p);
								if (n.p+oldEvent.size > pool.topAddr) throw new Exception(format("Node doesn't fit in the pool (node: %08X -> %08X, pool: %08X -> %08X)", n.p, n.p+oldEvent.size, pool.addr, pool.topAddr));
								if (n.p & 0xF) throw new Exception("Node is not aligned to paragraph boundary");
								bool doFree;
								if (oldEvent.size <= PAGESIZE/2) // B_2048
								{
									uint biti = (n.p-pool.addr)/16;
									//doFree = (!Pool.readBit(prevPool.freebits, biti) && Pool.readBit(pool.freebits, biti));  // non-free -> free
									doFree = Pool.readBit(pool.freebits, biti);
								}
								else
								{
									if (n.p & 0xFFF) throw new Exception("B_PAGE node is not aligned to page boundary");
									uint pagenum = (n.p-pool.addr) / PAGESIZE;
									if (prevPool.pagetable[pagenum] != B_PAGE) throw new Exception("Expected B_PAGE");
									if (pool.pagetable[pagenum] != B_PAGE && pool.pagetable[pagenum] != B_FREE) throw new Exception("Expected B_PAGE or B_FREE");
									doFree = pool.pagetable[pagenum] == B_FREE;
								}
								if (doFree)
									freeNodes ~= n;
							}
							catch(Exception e)
								throw new Exception(format("Error while synchronizing node allocated by #%d at %08X: %s", n.eventID, n.p, e.msg));
						foreach (n;freeNodes)
						{
							unmapNode(n.p, getNodeSize(n));
							removeNode(n);
						}
						break;
					}
					case PACKET_MEMORY_DUMP:
					{
						auto event = cast(MemoryDumpEvent)log.events[cursor];
						if (freeCheck)
							for (auto bin=B_16;bin<B_PAGE;bin++)
								try
								{
									uint prev = 0;
									uint p = event.buckets[bin];
									while (p)
									{
										string prevstr() { return prev ? format("following %08X", prev) : "first list item"; }
										
										auto pool = event.findPool(p);
										if (pool is null) throw new Exception(format("Free list item %08X (%s) does not belong in any memory pool", p, prevstr));
										if (p >= pool.topCommittedAddr) throw new Exception(format("Free list item %08X (%s) is pointing to a reserved memory region", p, prevstr));
										
										uint pagenum = (p-pool.addr) / PAGESIZE;
										if (pool.pagetable[pagenum] != bin)
											throw new Exception(format("Free list item %08X (%s) is in a wrong page (%s)", p, prevstr, pageNames[pool.pagetable[pagenum]]));
										if (p & (pageSizes[bin]-1))
											throw new Exception(format("Free list item %08X (%s) is not aligned to the bin boundary", p, prevstr));
										auto node = findNode(p);
										if (node !is null)
											throw new Exception(format("Free list item %08X (%s) is pointing to an occupied memory node (event #%d)", p, prevstr, node.eventID));
									
										prev = p;
										p = event.readDword(p); // this should always succeed
									}
								}
								catch(Exception e)
									throw new Exception(format("Error while checking free list for %s: %s", pageNames[bin], e.msg));
						break;
					}
					case PACKET_TEXT:
						break;
					default:
						throw new Exception(format("Unknown packet type %d", log.events[cursor].type));
				}
			catch(Exception e)
				throw new Exception(format("Error while processing event #%d: %s", cursor--, e.msg));
		}
	}

	uint getNodeSize(Node* n)
	{
		return (cast(MemoryAllocationEvent)log.events[n.eventID]).size;
	}
	
	void addNode(Node* n)
	{
		Node* post = null;
		/+for (uint para=n.p>>16;para<0x10000;para++)
			if (map[para])
			{
				post = map[para];
				break;
			}+/
		post = findNodeFuzzy(n.p);
		if (post is null) post=first;
		while (post && post.p<n.p)
			post = post.next;
		// insert n before post
		n.prev = post ? post.prev : last;
		n.next = post;
        *(n.prev ? &n.prev.next : &first) = n;
		*(n.next ? &n.next.prev : &last ) = n;
		if (n.prev && n.prev.p+getNodeSize(n.prev) > n.p) throw new Exception("Continuity broken, or allocating over occupied region");
		if (n.next && n.     p+getNodeSize(n) > n.next.p) throw new Exception("Continuity broken, or allocating over occupied region");
	}

	void removeNode(Node* n)
	{
		*(n.prev ? &n.prev.next : &first) = n.next;
		*(n.next ? &n.next.prev : &last ) = n.prev;
	}

	void mapNode(Node* n, uint size)
	{
		for (uint p=n.p;p<n.p+size;p+=0x10000)
			if (map[p>>16] is null || map[p>>16].p>p)
				map[p>>16] = n;
	}

	void unmapNode(uint op, uint size)
	{
		for (uint p=op;p<op+size;p+=0x10000)
		{
			auto n = map[p>>16];
			if (n !is null && n.p == op)
				if (n.next !is null && (n.next.p>>16) == (p>>16))
					map[p>>16] = n.next;
				else
					map[p>>16] = null;
		}
		//debug foreach (seg,n;map)
		//	if (n && n.p == op) throw new Exception(format("Unmap failed: unmapped %08X - %08X but it's still mapped at %08X", op, op+size, seg*0x10000));
	}

	Node* findNode(uint p)
	{
		auto n = map[p>>16];
		while (n && (n.p>>16)<=(p>>16))
			if (n.p <= p && (n.next is null || n.next.p > p))
			{
				auto event = cast(MemoryAllocationEvent)log.events[n.eventID];
				if (p < n.p + event.size)
					return n;
				else
					return null;
			}
			else
				n = n.next;
		return null;
	}

	Node* findNodeFuzzy(uint p)
	{
		auto sector = p>>16;
		while (sector && map[sector] is null)
			sector--;
		if (!sector)
			return null;
		auto n = map[sector];
		/+while (n && n.p > p)
			n = n.prev;
		if (n is null)
			return null;+/
		while (n.next && n.next.p <= p)
			n = n.next;
		return n;
	}

	void reset()
	{
		map[] = null;
		first = last = null;
		cursor = -1;
	}

	Node* trace(Node* target, MemoryStateEvent event, MemoryDumpEvent dataEvent)
	{
		for (auto n=first; n; n=n.next)
			n.trace.state = TraceState.WHITE;
		target.trace.state = TraceState.GRAY;

		bool changed = true;
		while (changed)
		{
			// check roots
			struct Range
			{
				Node* n;
				uint min, max;
			}
			Range[] ranges;
			for (auto n=first; n; n=n.next)
				if (n.trace.state == TraceState.GRAY)
				{
					ranges ~= Range(n, n.p, n.p+getNodeSize(n));
					n.trace.state = TraceState.BLACK;
				}

			Node* checkRange(uint v)
			{
				foreach (ref r; ranges)
					if (r.min <= v && v < r.max)
						return r.n;
				return null;
			}

			Node* makeRoot(uint a, uint v, Node* n)
			{
				auto r = new Node;
				r.trace = TraceInfo(a, v, n);
				return r;
			}

			Node* next;

			{
				uint[] data = cast(uint[])dataEvent.loadStackData();
				scope(success) delete data;
				foreach (i,v;data)
					if ((next=checkRange(v))!is null)
						return makeRoot(dataEvent.stackTop + i*uint.sizeof, v, next);
			}

			foreach (rootIndex, ref root; dataEvent.roots)
				if (root.top - root.bottom != 0)
				{
					uint[] data = cast(uint[])dataEvent.loadRootData(root);
					scope(success) delete data;
					foreach (i,v;data)
						if ((next=checkRange(v))!is null)
							return makeRoot(root.bottom + i*uint.sizeof, v, next);
					delete data;
				}

			// expand search
			changed = false;
			foreach (int poolNr,ref pool;event.pools)
				for (int pageNr=0;pageNr<pool.ncommitted;pageNr++)
				{
					uint[] data = cast(uint[])dataEvent.loadPageData(poolNr, pageNr);
					scope(success) delete data;
					foreach (i,v;data)
						if ((next=checkRange(v))!is null)
						{
							uint address = pool.addr + pageNr*PAGESIZE + i*uint.sizeof;
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

							Node* n = findNode(address);
							if (n is null)
								throw new Exception(format("Reference from unmapped address %08X", address));
							if (n.trace.state != TraceState.WHITE)
								continue;
							n.trace.state = TraceState.GRAY;
							n.trace.from = address;
							n.trace.to = v;
							n.trace.next = next;
							changed = true;
						}
				}
		}
		return null;
	}
}

struct Node
{
	Node* next, prev;
	uint eventID;
	uint p;
	TraceInfo trace;
}

private enum TraceState
{
	WHITE,
	GRAY,
	BLACK,
}

private struct TraceInfo
{
	uint from, to;
	Node* next;
	TraceState state;
}
