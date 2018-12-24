module test.sparc;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum SPARC_CODE = cast(ubyte[])"\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03";
enum SPARCV9_CODE = cast(ubyte[])"\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0";

enum platforms = [
	Platform(Arch.sparc, Mode.bigEndian, SPARC_CODE, "Sparc"),
	Platform(Arch.sparc, Mode.bigEndian + Mode.sparcV9, SPARCV9_CODE, "SparcV9"),
];

void writeDetail(ref OutBuffer buf, in InstructionSparc instr, in CapstoneSparc cs){
	assert(!instr.detail.isNull);
	auto sparc = instr.detail; // = instr.detail.archSpecific;
	
	if(sparc.operands.length > 0)
		buf.writefln("\top_count: %d", sparc.operands.length);

	foreach(i, operand; sparc.operands){
		final switch(operand.type){
			case SparcOpType.invalid:
				break;
			case SparcOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(operand.reg));
				break;
			case SparcOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case SparcOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (operand.mem.base != SparcRegister.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(operand.mem.base));
				if (operand.mem.index != SparcRegister.invalid)
					buf.writefln("\t\t\toperands[%u].mem.index: REG = %s", i, cs.regName(operand.mem.index));
				if (operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				break;
		}
	}

	if (sparc.cc != SparcCc.invalid)
		buf.writefln("\tCode condition: %u", sparc.cc);
	if (sparc.hint.to!uint != 0)
		buf.writefln("\tHint code: %s", sparc.hint.to!uint);
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.sparc);
		auto cs = new CapstoneSparc(ModeFlags(platform.mode));
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

	const expected = import("sparc.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}