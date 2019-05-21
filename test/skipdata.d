module test.skipdata;

import std.array: array;
import std.algorithm: filter;
import std.string: representation;
import std.outbuffer: OutBuffer;
import std.functional: toDelegate;

import capstone;
import test.utils;

enum X86_CODE32 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
enum RANDOM_CODE = cast(ubyte[])"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78";

size_t mycallback(in ubyte[] code, size_t offset) nothrow @nogc{
    return 2; // Always skip 2 bytes when encountering data
}

unittest{
    // Setting platforms at runtime (cannot set delegate at compile-time)
    const platforms = [
        Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (Intel syntax) - Skip data", Syntax.systemDefault),
        Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (Intel syntax) - Skip data with custom mnemonic", Syntax.systemDefault, "db"),
        Platform(Arch.arm, Mode.arm, RANDOM_CODE, "Arm - Skip data", Syntax.systemDefault),
        Platform(Arch.arm, Mode.arm, RANDOM_CODE, "Arm - Skip data with callback", Syntax.systemDefault, "db", toDelegate(&mycallback))
    ];

    auto buf = new OutBuffer;
    foreach(i, platform; platforms) {
        auto cs = create(platform.arch, ModeFlags(platform.mode));
        if(platform.syntax)
            cs.syntax = platform.syntax;
        cs.detail = true;
        cs.skipData = true;

        if(platform.skipdataMnemonic)
            cs.setupSkipdata(platform.skipdataMnemonic, platform.callback);
        
        auto res = cs.disasm(platform.code, 0x1000);
        assert(res.length > 0);

        buf.writefln("****************");
        buf.writefln("Platform: %s", platform.comment);
        buf.writefln("Code: %s", platform.code.bytesToHex);
        buf.writefln("Disasm:");

        foreach(instr; res)
            buf.writefln("0x%x:\t%s\t\t%s", instr.address, instr.mnemonic, instr.opStr);
        buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
        buf.writefln("");
    }

    const expected = import("skipdata.expected");
    const actual = buf.toString;

    assert(expected == actual, expectationMismatch(expected, actual));
}
