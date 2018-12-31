module test.arm;

import std.outbuffer;
import std.conv: to;
import std.range: empty;
import std.array: join;
import std.algorithm: map;

import capstone;
import capstone.arm;
import test.utils;

enum ARM_CODE = cast(ubyte[])"\x86\x48\x60\xf4\x4d\x0f\xe2\xf4\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00";
enum ARM_CODE2 = cast(ubyte[])"\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c";
enum THUMB_CODE = cast(ubyte[])"\x60\xf9\x1f\x04\xe0\xf9\x4f\x07\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84\x52\xf8\x23\xf0";
enum THUMB_CODE2 = cast(ubyte[])"\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0\x18\xbf\xad\xbf\xf3\xff\x0b\x0c\x86\xf3\x00\x89\x80\xf3\x00\x8c\x4f\xfa\x99\xf6\xd0\xff\xa2\x01";
enum THUMB_MCLASS = cast(ubyte[])"\xef\xf3\x02\x80";
enum ARMV8 = cast(ubyte[])"\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5";

enum platforms = [
	Platform(Arch.arm, Mode.arm, ARM_CODE, "ARM"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE, "Thumb"),
	Platform(Arch.arm, Mode.armThumb, ARM_CODE2, "Thumb-mixed"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE2, "Thumb-2 & register named with numbers", Syntax.noregname),
	Platform(Arch.arm, Mode.armThumb + Mode.armCortexM, THUMB_MCLASS, "Thumb-MClass"),
	Platform(Arch.arm, Mode.arm + Mode.armV8, ARMV8, "Arm-V8")
];

void writeDetail(ref OutBuffer buf, in InstructionArm instr, in CapstoneArm cs){
	assert(!instr.detail.isNull);
	auto arm = instr.detail; // = instr.detail.archSpecific;
	
	if(arm.operands.length > 0)
		buf.writefln("\top_count: %d", arm.operands.length);
	foreach(i, operand; arm.operands){
		final switch(operand.type){
			case ArmOpType.invalid:
				break;
			case ArmOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(operand.reg));
				break;
			case ArmOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case ArmOpType.fp:
				buf.writefln("\t\toperands[%d].type: FP = %f", i, operand.fp);
				break;
			case ArmOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (operand.mem.base != ArmRegister.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(operand.mem.base));
				if (operand.mem.index != ArmRegister.invalid)
					buf.writefln("\t\t\toperands[%d].mem.index: REG = %s", i, cs.regName(operand.mem.index));
				if (operand.mem.scale != 1)
					buf.writefln("\t\t\toperands[%d].mem.scale: %d", i, operand.mem.scale);
				if (operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				break;
			case ArmOpType.pimm:
				buf.writefln("\t\toperands[%d].type: P-IMM = %d", i, operand.imm);
				break;
			case ArmOpType.cimm:
				buf.writefln("\t\toperands[%d].type: C-IMM = %d", i, operand.imm);
				break;
			case ArmOpType.setend:
				buf.writefln("\t\toperands[%d].type: SETEND = %s", i, operand.setend == ArmSetendType.be? "be" : "le");
				break;
			case ArmOpType.sysreg:
				buf.writefln("\t\toperands[%d].type: SYSREG = %d", i, operand.reg);
				break;
		}

		if (operand.neonLane != -1)
			buf.writefln("\t\toperands[%u].neon_lane = %u", i, operand.neonLane);

		if(operand.access)
			buf.writefln("\t\toperands[%u].access: %s", i, operand.access.accessToString);

		if (operand.shift.type != ArmShiftType.invalid && operand.shift.value) {
			if (operand.shift.type < ArmShiftType.asr_reg) // shift with constant value
				buf.writefln("\t\t\tShift: %d = %d", operand.shift.type, operand.shift.value);
			else // shift with register
				buf.writefln("\t\t\tShift: %d = %s", operand.shift.type, cs.regName(operand.shift.value.to!ArmRegister));
		}

		if (operand.vectorIndex != -1)
			buf.writefln("\t\toperands[%d].vector_index = %d", i, operand.vectorIndex);
		if (operand.subtracted)
			buf.writefln("\t\tSubtracted: True");
	}

	if (arm.cc != ArmCc.al && arm.cc != ArmCc.invalid)
		buf.writefln("\tCode condition: %d", arm.cc);
	if (arm.updateFlags)
		buf.writefln("\tUpdate-flags: True");
	if (arm.writeback)
		buf.writefln("\tWrite-back: True");
	if (arm.cpsMode)
		buf.writefln("\tCPSI-mode: %d", arm.cpsMode);
	if (arm.cpsFlag)
		buf.writefln("\tCPSI-flag: %d", arm.cpsFlag);
	if (arm.vectorData)
		buf.writefln("\tVector-data: %d", arm.vectorData);
	if (arm.vectorSize)
		buf.writefln("\tVector-size: %d", arm.vectorSize);
	if (arm.usermode)
		buf.writefln("\tUser-mode: True");
	if (arm.memBarrier)
		buf.writefln("\tMemory-barrier: %d", arm.memBarrier);

	auto regsAccess = cs.regsAccess(instr);
	if (!regsAccess.read.empty)
		buf.writefln("\tRegisters read: %s", regsAccess.read.map!(reg => cs.regName(reg)).join(" "));
	if (!regsAccess.write.empty)
		buf.writefln("\tRegisters modified: %s", regsAccess.write.map!(reg => cs.regName(reg)).join(" "));
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.arm);
		auto cs = new CapstoneArm(ModeFlags(platform.mode));
		cs.syntax = platform.syntax;
		cs.detail = true;
		
		auto res = cs.disasm(platform.code, 0x80001000);
		assert(res.length > 0);

		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code:%s", platform.code.bytesToHex);
		buf.writefln("Disasm:");

		foreach(instr; res){
			buf.writefln("0x%x:\t%s\t%s", instr.address, instr.mnemonic, instr.opStr);
			buf.writeDetail(instr, cs);
		}
		buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
		buf.writefln("");
	}

	const expected = import("arm.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}