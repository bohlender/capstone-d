module test.sysz;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum SYSZ_CODE = cast(ubyte[])"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78\xec\x18\x00\x00\xc1\x7f";

enum platforms = [
	Platform(Arch.sysz, Mode.bigEndian, SYSZ_CODE, "SystemZ"),
];

void writeDetail(ref OutBuffer buf, in InstructionSysz instr, in CapstoneSysz cs){
	assert(!instr.detail.isNull);
	auto sysz = instr.detail; // = instr.detail.archSpecific;
	
	if(sysz.operands.length > 0)
		buf.writefln("\top_count: %d", sysz.operands.length);
	foreach(i, operand; sysz.operands){
		final switch(operand.type){
			case SyszOpType.invalid:
				break;
			case SyszOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(operand.reg));
				break;
			case SyszOpType.acreg:
				buf.writefln("\t\toperands[%u].type: ACREG = %u", i, operand.reg);
				break;
			case SyszOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case SyszOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (operand.mem.base != SyszRegister.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(operand.mem.base));
				if (operand.mem.index != SyszRegister.invalid)
					buf.writefln("\t\t\toperands[%u].mem.index: REG = %s", i, cs.regName(operand.mem.index));
				if (operand.mem.length != 0)
					buf.writefln("\t\t\toperands[%u].mem.length: 0x%x", i, operand.mem.length);
				if (operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				break;
		}
	}
	if (sysz.cc != SyszCc.invalid)
		buf.writefln("\tCode condition: %u", sysz.cc);
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.sysz);
		auto cs = new CapstoneSysz(ModeFlags(platform.mode));
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

	const expected = import("sysz.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}