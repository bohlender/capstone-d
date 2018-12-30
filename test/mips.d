module test.mips;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum MIPS_CODE = cast(ubyte[])"\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56";
enum MIPS_CODE2 = cast(ubyte[])"\x56\x34\x21\x34\xc2\x17\x01\x00";
enum MIPS_32R6M = cast(ubyte[])"\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0";
enum MIPS_32R6 = cast(ubyte[])"\xec\x80\x00\x19\x7c\x43\x22\xa0";
enum MIPS_64SD = cast(ubyte[])"\x70\x00\xb2\xff";

enum platforms = [
	Platform(Arch.mips, Mode.mips32 + Mode.bigEndian, MIPS_CODE, "MIPS-32 (Big-endian)"),
	Platform(Arch.mips, Mode.mips64 + Mode.littleEndian, MIPS_CODE2, "MIPS-64-EL (Little-endian)"),
	Platform(Arch.mips, Mode.mips32r6 + Mode.mipsMicro + Mode.bigEndian, MIPS_32R6M, "MIPS-32R6 | Micro (Big-endian)"),
	Platform(Arch.mips, Mode.mips32r6 + Mode.bigEndian, MIPS_32R6, "MIPS-32R6 (Big-endian)"),
	Platform(Arch.mips, Mode.mips64 + Mode.mips2 + Mode.littleEndian, MIPS_64SD, "MIPS-64-EL + Mips II (Little-endian)"),
	Platform(Arch.mips, Mode.mips64 + Mode.littleEndian, MIPS_64SD, "MIPS-64-EL (Little-endian)")
];

void writeDetail(ref OutBuffer buf, in InstructionMips instr, in CapstoneMips cs){
	assert(!instr.detail.isNull);
	auto mips = instr.detail; // = instr.detail.archSpecific;
	
	if(mips.operands.length > 0)
		buf.writefln("\top_count: %d", mips.operands.length);
	foreach(i, operand; mips.operands){
		final switch(operand.type){
			case MipsOpType.invalid:
				break;
			case MipsOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(operand.reg));
				break;
			case MipsOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case MipsOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (operand.mem.base != MipsRegister.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(operand.mem.base));
				if (operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				break;
		}
	}
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.mips);
		auto cs = new CapstoneMips(ModeFlags(platform.mode));
		cs.detail = true;
		
		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code:%s", platform.code.bytesToHex);

		auto res = cs.disasm(platform.code, 0x1000);
		if(res.length > 0){
			buf.writefln("Disasm:");
			foreach(instr; res){
				buf.writefln("0x%x:\t%s\t%s", instr.address, instr.mnemonic, instr.opStr);
				buf.writeDetail(instr, cs);
			}
			buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
		}else{
			buf.writefln("ERROR: Failed to disasm given code!");
		}
		buf.writefln("");
	}

	const expected = import("mips.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}