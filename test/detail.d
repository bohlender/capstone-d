module test.detail;

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
enum THUMB_MCLASS = cast(ubyte[])"\xef\xf3\x02\x80";
enum ARMV8 = cast(ubyte[])"\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5";
enum MIPS_CODE = cast(ubyte[])"\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56\x00\x80\x04\x08";
enum MIPS_CODE2 = cast(ubyte[])"\x56\x34\x21\x34\xc2\x17\x01\x00";
enum MIPS_32R6M = cast(ubyte[])"\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0";
enum MIPS_32R6 = cast(ubyte[])"\xec\x80\x00\x19\x7c\x43\x22\xa0";
enum ARM64_CODE = cast(ubyte[])"\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c";
enum PPC_CODE = cast(ubyte[])"\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21\x40\x82\x00\x14";
enum PPC_CODE2 = cast(ubyte[])"\x10\x60\x2a\x10\x10\x64\x28\x88\x7c\x4a\x5d\x0f";
enum SPARC_CODE = cast(ubyte[])"\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03";
enum SPARCV9_CODE = cast(ubyte[])"\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0";
enum SYSZ_CODE = cast(ubyte[])"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78";
enum XCORE_CODE = cast(ubyte[])"\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10";
enum M68K_CODE = cast(ubyte[])"\xd4\x40\x87\x5a\x4e\x71\x02\xb4\xc0\xde\xc0\xde\x5c\x00\x1d\x80\x71\x12\x01\x23\xf2\x3c\x44\x22\x40\x49\x0e\x56\x54\xc5\xf2\x3c\x44\x00\x44\x7a\x00\x00\xf2\x00\x0a\x28";

enum platforms = [
	Platform(Arch.x86, Mode.bit16, X86_CODE16, "X86 16bit (Intel syntax)"),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32bit (ATT syntax)", Syntax.att),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (Intel syntax)"),
	Platform(Arch.x86, Mode.bit64, X86_CODE64, "X86 64 (Intel syntax)"),
	Platform(Arch.arm, Mode.arm, ARM_CODE, "ARM"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE2, "THUMB-2"),
	Platform(Arch.arm, Mode.arm, ARM_CODE2, "ARM: Cortex-A15 + NEON"),
	Platform(Arch.arm, Mode.armThumb, THUMB_CODE, "THUMB"),
	Platform(Arch.arm, Mode.armThumb + Mode.armCortexM, THUMB_MCLASS, "Thumb-MClass"),
	Platform(Arch.arm, Mode.arm + Mode.armV8, ARMV8, "Arm-V8"),
	Platform(Arch.mips, Mode.mips32 + Mode.bigEndian, MIPS_CODE, "MIPS-32 (Big-endian)"),
	Platform(Arch.mips, Mode.mips64 + Mode.littleEndian, MIPS_CODE2, "MIPS-64-EL (Little-endian)"),
	Platform(Arch.mips, Mode.mips32r6 + Mode.mipsMicro + Mode.bigEndian, MIPS_32R6M, "MIPS-32R6 | Micro (Big-endian)"),
	Platform(Arch.mips, Mode.mips32r6 + Mode.bigEndian, MIPS_32R6, "MIPS-32R6 (Big-endian)"),
	Platform(Arch.arm64, Mode.arm, ARM64_CODE, "ARM-64"),
	Platform(Arch.ppc, Mode.bigEndian, PPC_CODE, "PPC-64"),
	Platform(Arch.ppc, Mode.bigEndian + Mode.qpx, PPC_CODE2, "PPC-64 + QPX"),
	Platform(Arch.sparc, Mode.bigEndian, SPARC_CODE, "Sparc"),
	Platform(Arch.sparc, Mode.bigEndian + Mode.sparcV9, SPARCV9_CODE, "SparcV9"),
	Platform(Arch.sysz, Mode.littleEndian, SYSZ_CODE, "SystemZ"),
	Platform(Arch.xcore, Mode.littleEndian, XCORE_CODE, "XCore"),
	Platform(Arch.m68k, Mode.bigEndian + Mode.m68k_040, M68K_CODE, "M68K"),
];

void writeDetail(ref OutBuffer buf, in Instruction instr) {
	buf.writefln("0x%x:\t%s\t\t%s // insn-ID: %d, insn-mnem: %s", instr.address, instr.mnemonic, instr.opStr, instr.idAsInt, instr.name);
	const detail = instr.detail;
	if(detail.regsRead.length > 0) {
		buf.writef("\tImplicit registers read: ");
		foreach(reg; detail.regsRead)
			buf.writef("%s ", reg.name);
		buf.writefln("");
	}
	if(detail.regsWrite.length > 0) {
		buf.writef("\tImplicit registers modified: ");
		foreach(reg; detail.regsWrite)
			buf.writef("%s ", reg.name);
		buf.writefln("");
	}
	if(detail.groups.length > 0) {
		buf.writef("\tThis instruction belongs to groups: ");
		foreach(group; detail.groups)
			buf.writef("%s ", group.name);
		buf.writefln("");
	}
}

unittest{
	auto buf = new OutBuffer;
	foreach(i, platform; platforms) {{
		// Weird code structure to be consistent with original tests in C
		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		auto cs = create(platform.arch, ModeFlags(platform.mode));
		if(platform.syntax != Syntax.systemDefault)
			cs.syntax = platform.syntax;
		cs.detail = true;

		auto res = cs.disasm(platform.code, 0x1000);
		if(res.length > 0){
			buf.writefln("Code: %s", platform.code.bytesToHex);
			buf.writefln("Disasm:");

			foreach(instr; res)
				buf.writeDetail(instr);
			buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
		}else{
			buf.writefln("****************");
			buf.writefln("Platform: %s", platform.comment);
			buf.writefln("Code: %s", platform.code.bytesToHex);
			buf.writefln("ERROR: Failed to disasm given code!");
		}
		buf.writefln("");
	}}

	const expected = import("detail.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}