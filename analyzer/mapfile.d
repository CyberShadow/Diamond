module mapfile;

import std.file;
import std.string;
import std.c.stdio;
import std.demangle;

struct Symbol
{
	uint address;
	string name;

	int opCmp(Symbol* s) 
	{
		return address==s.address?0:address<s.address?-1:1;
	}

	string prettyName()
	{
		string result;
		try
			result = demangle(name);
		catch(Object o)
			result = name;
		foreach (ref c;result)
			if (c>=0x80)
				c = '?';
		return result;
	}
}

final class MapFile
{
	this(string fileName)
	{
		auto lines = splitlines(cast(string)read(fileName));
		bool parsing = false;
		foreach (line;lines)
		{
			// OPTLINK format
			if (parsing)
			{
				if (line.length > 30 && line[5]==':' && line[17]==' ')
				{
					// 0002:00078A44       _D5win327objbase11IsEqualGUIDFS5win328basetyps4GUIDS5win328basetyps4GUIDZi 0047CA44
					Symbol s;
					auto line2 = line[21..$];
					s.name = line2[0..find(line2, ' ')];
					sscanf(toStringz(line2[$-8..$]), "%x", &s.address);
					symbols ~= s;
				}
			}
			else
				if (find(line, "Publics by Value")>0)
					parsing = true;
				
			// LD format
			auto stripped = line.strip();
			//                 0x00000000080eaa10                _D20TypeInfo_E2WA6Nation6__initZ
			if (stripped.length>10 && stripped[0..2]=="0x")
			{
				auto words = stripped.split();
				if (words.length != 2)
					continue;
				Symbol s;
				s.name = words[1];
				sscanf(toStringz(words[0][2..$]), "%x", &s.address);
				symbols ~= s;
			}
		}
		symbols.sort;
	}

final:
	string lookup(uint address)
	{
		uint min=0, max=symbols.length-1;
		while (min<=max)
		{
			uint mid = (min+max)/2;
			if (mid<0 || mid>=symbols.length) break;
			if (symbols[mid].address <= address && (mid+1==symbols.length || symbols[mid+1].address>address))
				return symbols[mid].prettyName ~ (symbols[mid].address==address ? "" : format(" +%x", address - symbols[mid].address));
			else
			if (symbols[mid].address > address)
				max = mid - 1;
			else
				min = mid + 1;
		}
		return format("%08X", address);
	}

	Symbol[] symbols;
}
