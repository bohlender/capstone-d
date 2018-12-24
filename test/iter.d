module test.iter;

import std.outbuffer;

import capstone;
import test.utils;

enum X86_CODE16 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
enum X86_CODE32 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
enum X86_CODE64 = cast(ubyte[])"\x55\x48\x8b\x05\xb8\x13\x00\x00";
enum ARM_CODE = cast(ubyte[])"\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3";
enum ARM_CODE2 = cast(ubyte[])"\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3";
enum THUMB_CODE = cast(ubyte[])"\x70\x47\xeb\x46\x83\xb0\xc9\x68";
enum THUMB_CODE2 = cast(ubyte[])"\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0";
enum MIPS_CODE = cast(ubyte[])"\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56\x00\x80\x04\x08";
enum MIPS_CODE2 = cast(ubyte[])"\x56\x34\x21\x34\xc2\x17\x01\x00";
enum ARM64_CODE = cast(ubyte[])"\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c";
enum PPC_CODE = cast(ubyte[])"\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21\x40\x82\x00\x14";
enum SPARC_CODE = cast(ubyte[])"\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03";
enum SPARCV9_CODE = cast(ubyte[])"\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0";
enum SYSZ_CODE = cast(ubyte[])"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78";
enum XCORE_CODE = cast(ubyte[])"\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10";

// TODO: Add missing tests when all archs are supported
/*
enum platforms = [
	Platform(Arch.x86, Mode.bit16, X86_CODE16, "X86 16bit (Intel syntax)"),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32bit (ATT syntax)", Syntax.att),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (Intel syntax)"),
	Platform(Arch.x86, Mode.bit64, X86_CODE64, "X86 64 (Intel syntax)"),
	Platform(Arch.arm, Mode.arm, ARM_CODE, "ARM"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE2, "THUMB-2"),
	Platform(Arch.arm, Mode.arm, ARM_CODE2, "ARM: Cortex-A15 + NEON"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE, "THUMB"),
	Platform(Arch.mips, Mode.mips32 + Mode.bigEndian, MIPS_CODE, "MIPS-32 (Big-endian)"),
	Platform(Arch.mips, Mode.mips64 + Mode.littleEndian, MIPS_CODE2, "MIPS-64-EL (Little-endian)"),
	Platform(Arch.arm64, Mode.arm, ARM64_CODE, "ARM-64"),
	Platform(Arch.powerPc, Mode.bigEndian, PPC_CODE, "PPC-64"),
	Platform(Arch.sparc, Mode.bigEndian, SPARC_CODE, "Sparc"),
	Platform(Arch.sparc, Mode.bigEndian + Mode.sparcV9, SPARCV9_CODE, "SparcV9"),
	Platform(Arch.systemZ, Mode.littleEndian, SYSZ_CODE, "SystemZ"),
	Platform(Arch.xCore, Mode.littleEndian, XCORE_CODE, "XCore")
]*/
enum platforms = [
	Platform(Arch.x86, Mode.bit16, X86_CODE16, "X86 16bit (Intel syntax)"),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32bit (ATT syntax)", Syntax.att),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (Intel syntax)"),
	Platform(Arch.x86, Mode.bit64, X86_CODE64, "X86 64 (Intel syntax)"),
	Platform(Arch.arm, Mode.arm, ARM_CODE, "ARM"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE2, "THUMB-2"),
	Platform(Arch.arm, Mode.arm, ARM_CODE2, "ARM: Cortex-A15 + NEON"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE, "THUMB"),
	Platform(Arch.mips, Mode.mips32 + Mode.bigEndian, MIPS_CODE, "MIPS-32 (Big-endian)"),
	Platform(Arch.mips, Mode.mips64 + Mode.littleEndian, MIPS_CODE2, "MIPS-64-EL (Little-endian)"),
	Platform(Arch.arm64, Mode.arm, ARM64_CODE, "ARM-64"),
	Platform(Arch.ppc, Mode.bigEndian, PPC_CODE, "PPC-64"),
];

void writeDetail(Arch arch)(ref OutBuffer buf, in InstructionImpl!arch instr, in CapstoneImpl!arch cs) {
	buf.writefln("0x%x:\t%s\t\t%s // insn-ID: %d, insn-mnem: %s", instr.address, instr.mnemonic, instr.opStr, instr.id, cs.instrName(instr.id));
	auto detail = instr.detail;
	if(detail.regsRead.length > 0) {
		buf.writef("\tImplicit registers read: ");
		foreach(reg; detail.regsRead)
			buf.writef("%s ", cs.regName(reg));
		buf.writefln("");
	}
	if(detail.regsWrite.length > 0) {
		buf.writef("\tImplicit registers modified: ");
		foreach(reg; detail.regsWrite)
			buf.writef("%s ", cs.regName(reg));
		buf.writefln("");
	}
	if(detail.groups.length > 0) {
		buf.writef("\tThis instruction belongs to groups: ");
		foreach(group; detail.groups)
			buf.writef("%s ", cs.groupName(group));
		buf.writefln("");
	}
}

unittest{
	auto buf = new OutBuffer;
	foreach(i, platform; platforms) {
		auto cs = Capstone.create(platform.arch, ModeFlags(platform.mode));
		cs.syntax = platform.syntax;
		cs.detail = true;

		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code: %s", platform.code.bytesToHex);
		buf.writefln("Disasm:");

		foreach(instr; cs.disasmIter(platform.code, 0x1000)){ 
			switch(platform.arch){
				case Arch.arm:
					buf.writeDetail(cast(InstructionImpl!(Arch.arm))instr, cast(CapstoneImpl!(Arch.arm))cs);
					break;
				case Arch.arm64:
					buf.writeDetail(cast(InstructionImpl!(Arch.arm64))instr, cast(CapstoneImpl!(Arch.arm64))cs);
					break;
				case Arch.mips:
					buf.writeDetail(cast(InstructionImpl!(Arch.mips))instr, cast(CapstoneImpl!(Arch.mips))cs);
					break;
				case Arch.ppc:
					buf.writeDetail(cast(InstructionImpl!(Arch.ppc))instr, cast(CapstoneImpl!(Arch.ppc))cs);
					break;
				case Arch.x86:
					buf.writeDetail(cast(InstructionImpl!(Arch.x86))instr, cast(CapstoneImpl!(Arch.x86))cs);
					break;
				default:
					assert(false);
			}
		}
		buf.writefln("");
	}

	const expected = import("iter.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}