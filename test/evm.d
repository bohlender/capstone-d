module test.evm;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum EVM_CODE = cast(ubyte[])"\x60\x61\x50";

enum platforms = [
	Platform(Arch.evm, Mode.littleEndian, EVM_CODE, "EVM"),
];

void writeDetail(ref OutBuffer buf, in EvmInstruction instr){
	auto evm = instr.detail; // = instr.detail.archSpecific;

	if(evm.pop > 0)
		buf.writefln("\tPop:     %d", evm.pop);
	if(evm.push > 0)
		buf.writefln("\tPush:    %d", evm.push);
	if(evm.fee > 0)
		buf.writefln("\tGas fee: %d", evm.fee);
	
	if(evm.groups.length) {
		buf.writef("\tGroups: ");
		foreach(group; evm.groups)
			buf.writef("%s ", group.name);
		buf.writefln("");
	}
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.evm);
		auto cs = new CapstoneEvm(ModeFlags(platform.mode));
		cs.detail = true;
		
		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code:%s", platform.code.bytesToHex);

		auto res = cs.disasm(platform.code, 0x80001000);
		if(res.length > 0){
			buf.writefln("Disasm:");
			foreach(instr; res){
				buf.writefln("0x%x:\t%s\t%s", instr.address, instr.mnemonic, instr.opStr);
				buf.writeDetail(instr);
			}
			buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
		}else{
			buf.writefln("ERROR: Failed to disasm given code!");
		}
		buf.writefln("");
	}

	const expected = import("evm.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}