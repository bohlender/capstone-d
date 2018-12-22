import std.algorithm: map;
import std.array: replicate, join;
import std.format: format;
import std.stdio: writeln, writefln;
import std.traits: EnumMembers;

import capstone;

auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";

auto underline(in string s){return s ~ "\n" ~ "=".replicate(s.length);}
auto bytesToHex(in ubyte[] code){return code.map!(i => "0x%.2x".format(i)).join(" ");}

void main(){
    writefln!"Version: %s (lib), %s (bindings)"(versionOfLibrary, versionOfBindings);
    "Querying installed Capstone library for supported options:".underline.writeln;
    foreach(query; EnumMembers!SupportQuery)
        writefln!"%-10s: %s"(query, supports(query));

    auto cs = Capstone.create(Arch.x86, ModeFlags(Mode.bit32));
    cs.skipData = true;
    
    writefln!"\nDisassembling (%s): %s"(cs.arch, CODE.bytesToHex);
    auto res = cs.disasm(CODE, 0x1000);
    foreach(instr; res)
        writefln!"0x%x:\t%s\t\t%s"(instr.address, instr.mnemonic, instr.opStr);
}
