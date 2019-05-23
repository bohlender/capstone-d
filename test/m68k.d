module test.m68k;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum M68K_CODE = cast(ubyte[])"\x4C\x00\x54\x04\x48\xe7\xe0\x30\x4C\xDF\x0C\x07\xd4\x40\x87\x5a\x4e\x71\x02\xb4\xc0\xde\xc0\xde\x5c\x00\x1d\x80\x71\x12\x01\x23\xf2\x3c\x44\x22\x40\x49\x0e\x56\x54\xc5\xf2\x3c\x44\x00\x44\x7a\x00\x00\xf2\x00\x0a\x28\x4E\xB9\x00\x00\x00\x12\x4E\x75";

enum platforms = [
	Platform(Arch.m68k, Mode.bigEndian + Mode.m68k_040, M68K_CODE, "M68K"),
];

enum addressingModes = [
	"<invalid mode>",

	"Register Direct - Data",
	"Register Direct - Address",

	"Register Indirect - Address",
	"Register Indirect - Address with Postincrement",
	"Register Indirect - Address with Predecrement",
	"Register Indirect - Address with Displacement",

	"Address Register Indirect With Index - 8-bit displacement",
	"Address Register Indirect With Index - Base displacement",

	"Memory indirect - Postindex",
	"Memory indirect - Preindex",

	"Program Counter Indirect - with Displacement",

	"Program Counter Indirect with Index - with 8-Bit Displacement",
	"Program Counter Indirect with Index - with Base Displacement",

	"Program Counter Memory Indirect - Postindexed",
	"Program Counter Memory Indirect - Preindexed",

	"Absolute Data Addressing  - Short",
	"Absolute Data Addressing  - Long",
	"Immediate value",
];

void writeDetail(ref OutBuffer buf, in M68kInstruction instr){
	auto m68k = instr.detail; // = instr.detail.archSpecific;
	
	if(m68k.operands.length > 0)
		buf.writefln("\top_count: %d", m68k.operands.length);

	foreach(reg; m68k.regsRead)
		buf.writef("\treading from reg: %s\n", reg.name);
	foreach(reg; m68k.regsWrite)
		buf.writef("\twriting to reg:   %s\n", reg.name);

	buf.writefln("\tgroups_count: %d", m68k.groups.length);

	foreach(i, op; m68k.operands){
		switch(op.type){
			case M68kOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, op.reg.name);
				break;
			case M68kOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, cast(int)op.imm);
				break;
			case M68kOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (op.mem.baseReg.id != M68kRegisterId.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, op.mem.baseReg.name);
				if (op.mem.indexReg.id != M68kRegisterId.invalid) {
					buf.writefln("\t\t\toperands[%d].mem.index: REG = %s", i, op.mem.indexReg.name);
					buf.writefln("\t\t\toperands[%d].mem.index: size = %c", i, op.mem.indexSize > 0 ? 'l' : 'w');
				}
				if (op.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, op.mem.disp);
				if (op.mem.scale != 0)
					buf.writefln("\t\t\toperands[%d].mem.scale: %d", i, op.mem.scale);

				buf.writefln("\t\taddress mode: %s", addressingModes[op.addressMode]);
				break;
			case M68kOpType.fpSingle:
				buf.writefln("\t\toperands[%d].type: FP_SINGLE", i);
				buf.writefln("\t\t\toperands[%d].simm: %f", i, op.simm);
				break;
			case M68kOpType.fpDouble:
				buf.writefln("\t\toperands[%d].type: FP_DOUBLE", i);
				buf.writefln("\t\t\toperands[%d].dimm: %lf", i, op.dimm);
				break;
			default:
				break;
		}
	}

	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.m68k);
		auto cs = new CapstoneM68k(ModeFlags(platform.mode));
		cs.detail = true;
		
		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code: %s", platform.code.bytesToHex);

		auto res = cs.disasm(platform.code, 0x1000);
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

	const expected = import("m68k.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}