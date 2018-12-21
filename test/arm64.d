module test.arm64;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum ARM64_CODE = cast(ubyte[])"\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c";

enum platforms = [
	Platform(Arch.arm64, Mode.arm, ARM64_CODE, "ARM-64")
];

void writeDetail(ref OutBuffer buf, in InstructionArm64 instr, in CapstoneArm64 cs){
	assert(!instr.detail.isNull);
	auto arm64 = instr.detail; //auto arm64 = instr.detail.archSpecific;

	if (arm64.operands.length > 0)
		buf.writefln("\top_count: %d", arm64.operands.length);

	foreach(i, op; arm64.operands){
		final switch(op.type){
			case Arm64OpType.invalid:
				break;
			case Arm64OpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(op.reg));
				break;
			case Arm64OpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, op.imm);
				break;
			case Arm64OpType.fp:
				buf.writefln("\t\toperands[%d].type: FP = %f", i, op.fp);
				break;
			case Arm64OpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (op.mem.base != Arm64Register.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(op.mem.base));
				if (op.mem.index != Arm64Register.invalid)
					buf.writefln("\t\t\toperands[%d].mem.index: REG = %s", i, cs.regName(op.mem.index));
				if (op.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, op.mem.disp);
				break;
			case Arm64OpType.cimm:
				buf.writefln("\t\toperands[%d].type: C-IMM = %d", i, op.imm);
				break;
			case Arm64OpType.reg_mrs:
				buf.writefln("\t\toperands[%d].type: REG_MRS = 0x%x", i, op.reg);
				break;
			case Arm64OpType.reg_msr:
				buf.writefln("\t\toperands[%d].type: REG_MSR = 0x%x", i, op.reg);
				break;
			case Arm64OpType.pstate:
				buf.writefln("\t\toperands[%d].type: PSTATE = 0x%x", i, op.pstate);
				break;
			case Arm64OpType.sys:
				buf.writefln("\t\toperands[%d].type: SYS = 0x%x", i, op.sys);
				break;
			case Arm64OpType.prefetch:
				buf.writefln("\t\toperands[%d].type: PREFETCH = 0x%x", i, op.prefetch);
				break;
			case Arm64OpType.barrier:
				buf.writefln("\t\toperands[%d].type: BARRIER = 0x%x", i, op.barrier);
				break;
		}

		if(op.shift.type != Arm64ShiftType.invalid && op.shift.value)
			buf.writefln("\t\t\tShift: type = %d, value = %d", op.shift.type, op.shift.value);
		if(op.ext != Arm64Extender.invalid)
			buf.writefln("\t\t\tExt: %d", op.ext);
		if(op.vas != Arm64Vas.invalid)
			buf.writefln("\t\t\tVector Arrangement Specifier: 0x%x", op.vas);
		if(op.vess != Arm64Vess.invalid)
			buf.writefln("\t\t\tVector Element Size Specifier: %d", op.vess);
		if(op.vectorIndex != -1)
			buf.writefln("\t\t\tVector Index: %d", op.vectorIndex);
	}

	if (arm64.updateFlags)
		buf.writefln("\tUpdate-flags: True");
	if (arm64.writeback)
		buf.writefln("\tWrite-back: True");
	if (arm64.cc)
		buf.writefln("\tCode-condition: %d", arm64.cc);
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.arm64);
		auto cs = new CapstoneArm64(ModeFlags(platform.mode));
		cs.syntax = platform.syntax;
		cs.detail = true;
		
		auto res = cs.disasm(platform.code, 0x2c);
		assert(res.length > 0);

		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code: %s", platform.code.bytesToHex);
		buf.writefln("Disasm:");

		foreach(instr; res){
			buf.writefln("0x%x:\t%s\t%s", instr.address, instr.mnemonic, instr.opStr);
			buf.writeDetail(instr, cs);
		}
		buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
		buf.writefln("");
	}

	const expected = import("arm64.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}