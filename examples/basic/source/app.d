module app;

import capstone;

import std.algorithm: map;
import std.array: replicate, join;
import std.format: format;
import std.stdio: writeln, writefln;
import std.traits: EnumMembers;

auto underline(in string s){return s ~ "\n" ~ "=".replicate(s.length);}

struct CbData{
    int a = 1;
    int b = 2;
}

auto X86_CODE32 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
auto ARM_CODE = cast(ubyte[])"\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3";

auto bytesToHex(in ubyte[] code){
	return code.map!(i => "0x%.2x".format(i)).join(" ") ~ " "; // ugly terminal space needed to match original
}

void main(){
	writefln!"Version: %s (lib), %s (bindings)"(Capstone.versionOfLibrary, Capstone.versionOfBindings);
	"Querying Support:".underline.writeln;
	foreach(query; EnumMembers!SupportQuery)
		writefln!"%-10s: %s"(query, Capstone.supports(query));

	//auto cs = new Capstone(Arch.arm, ModeFlags(Mode.arm32));
	auto cs = new Capstone(Arch.x86, ModeFlags(Mode.bit32));
	//cs.syntax = Syntax.noregname;
	//cs.detail = true;
	//cs.skipData = true;
	// TODO: Continue with option CS_OPT_MEM
	auto data = CbData(3,4);
	
	size_t callback(in ubyte[] code, size_t offset) {
		return data.a;
	}
	//cs.setupSkipdata("asdf", &callback);

	auto code = X86_CODE32;
	writefln!"Code: %s"(code.bytesToHex);

	auto res = cs.disasm(code, 0x1000);
	foreach(instr; res)
    	writefln!"0x%x:\t%s\t\t%s"(instr.address, instr.mnemonic, instr.opStr);
}