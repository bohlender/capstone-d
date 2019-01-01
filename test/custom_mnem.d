module test.custom_mnem;

import std.outbuffer;
import std.conv: to;
import std.format: format;

import capstone;
import test.utils;

enum X86_CODE32 = cast(ubyte[])"\x75\x01";

void writeDisasmOne(ref OutBuffer buf, in CapstoneX86 cs){
	auto instrs = cs.disasm(X86_CODE32, 0x1000);
	// TODO: DMD v2.083.1 segfaults in build-mode=singleFile when using
	// auto codeHex = X86_CODE32.bytesToHex(false);
	// buf.writefln("%s\t\t%s\t%s", codeHex, instrs[0].mnemonic, instrs[0].opStr);
	foreach(b; X86_CODE32)
		buf.write("%02x ".format(b));
	buf.writefln("\t\t%s\t%s", instrs[0].mnemonic, instrs[0].opStr);
}

unittest{
	auto buf = new OutBuffer;
	auto cs = new CapstoneX86(ModeFlags(Mode.bit32));

	// 1. Print out the instruction in default setup.
	buf.writefln("Disassemble X86 code with default instruction mnemonic");
	buf.writeDisasmOne(cs);

	// Customized mnemonic JNE to JNZ using CS_OPT_MNEMONIC option
	buf.writefln("\nNow customize engine to change mnemonic from 'JNE' to 'JNZ'");
	cs.customMnemonic(X86InstructionId.jne, "jnz");

	// 2. Now print out the instruction in newly customized setup.
	buf.writeDisasmOne(cs);

	// Reset engine to use the default mnemonic of JNE
	buf.writefln("\nReset engine to use the default mnemonic");
	cs.customMnemonic(X86InstructionId.jne);

	// 3. Now print out the instruction in default setup.
	buf.writeDisasmOne(cs);

	const expected = import("custom_mnem.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}