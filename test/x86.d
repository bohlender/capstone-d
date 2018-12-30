module test.x86;

import std.array: array;
import std.algorithm: filter;
import std.string: representation, toUpper;
import std.outbuffer: OutBuffer;
import std.range: empty;
import std.array: join;
import std.algorithm: map;
import std.conv: to;

import capstone;
import test.utils;

enum X86_CODE16 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\x66\xe9\xb8\x00\x00\x00\x67\xff\xa0\x23\x01\x00\x00\x66\xe8\xcb\x00\x00\x00\x74\xfc";
enum X86_CODE32 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\xe9\xea\xbe\xad\xde\xff\xa0\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff";
enum X86_CODE64 = cast(ubyte[])"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff";

enum platforms = [
	Platform(Arch.x86, Mode.bit16, X86_CODE16, "X86 16bit (Intel syntax)"),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (AT&T syntax)", Syntax.att),
	Platform(Arch.x86, Mode.bit32, X86_CODE32, "X86 32 (Intel syntax)"),
	Platform(Arch.x86, Mode.bit64, X86_CODE64, "X86 64 (Intel syntax)")		
];

void writeDetail(ref OutBuffer buf, in InstructionX86 instr, in CapstoneX86 cs){
	assert(!instr.detail.isNull);
	auto x86 = instr.detail; //auto x86 = instr.detail.archSpecific;

	buf.writefln("\tPrefix:%s", x86.prefix.bytesToHex);
	buf.writefln("\tOpcode:%s", x86.opcode.bytesToHex);
	buf.writefln("\trex: 0x%x", x86.rex);
	buf.writefln("\taddr_size: %d", x86.addrSize);
	buf.writefln("\tmodrm: 0x%x", x86.modRM);
	if (x86.encoding.modrmOffset)
		buf.writefln("\tmodrm_offset: 0x%x", x86.encoding.modrmOffset);
	buf.writefln("\tdisp: 0x%x", x86.disp);
	if (x86.encoding.dispOffset)
		buf.writefln("\tdisp_offset: 0x%x", x86.encoding.dispOffset);
	if (x86.encoding.dispSize)
		buf.writefln("\tdisp_size: 0x%x", x86.encoding.dispSize);

	if(!(cs.mode & Mode.bit16)){
		buf.writefln("\tsib: 0x%x", x86.sib);
		if(x86.sibBase != X86Register.invalid)
			buf.writefln("\t\tsib_base: %s", cs.regName(x86.sibBase));
		if(x86.sibIndex != X86Register.invalid)
			buf.writefln("\t\tsib_index: %s", cs.regName(x86.sibIndex));
		if(x86.sibScale != 0)
			buf.writefln("\t\tsib_scale: %d", x86.sibScale);
	}

	if(x86.xopCc != X86XopCc.invalid)
		buf.writefln("\txop_cc: %u", x86.xopCc);
	if(x86.sseCc != X86SseCodeCondition.invalid)
		buf.writefln("\tsse_cc: %d", x86.sseCc);
	if(x86.avxCc != X86AvxCodeCondition.invalid)
		buf.writefln("\tavx_cc: %d", x86.avxCc);
	if(x86.avxSae)
		buf.writefln("\tavx_sae: %d", x86.avxSae);
	if(x86.avxRM != X86AvxRoundingMode.invalid)
		buf.writefln("\tavx_rm: %d", x86.avxRM);

	auto imms = x86.operands.filter!(op => op.type == X86OpType.imm).array;
	if(imms.length > 0){
		buf.writefln("\timm_count: %d", imms.length);
		foreach(i, op; imms){
			buf.writefln("\t\timms[%d]: 0x%x", i+1, op.value.imm);
			if (x86.encoding.immOffset)
				buf.writefln("\timm_offset: 0x%x", x86.encoding.immOffset);
			if (x86.encoding.immSize)
				buf.writefln("\timm_size: 0x%x", x86.encoding.immSize);
		}
	}

	buf.writefln("\top_count: %d", x86.operands.length);
	foreach(i, operand; x86.operands){
		final switch(operand.type){
			case X86OpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(operand.reg));
				break;
			case X86OpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case X86OpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if(operand.mem.segment != X86Register.invalid)
					buf.writefln("\t\t\toperands[%d].mem.segment: REG = %s", i, cs.regName(operand.mem.segment));
				if(operand.mem.base != X86Register.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(operand.mem.base));
				if(operand.mem.index != X86Register.invalid)
					buf.writefln("\t\t\toperands[%d].mem.index: REG = %s", i, cs.regName(operand.mem.index));
				if(operand.mem.scale != 1)
					buf.writefln("\t\t\toperands[%d].mem.scale: %d", i, operand.mem.scale);
				if(operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				break;
			case X86OpType.invalid:
				break;
		}

		if(operand.avxBcast != X86AvxBroadcast.invalid)
			buf.writefln("\t\toperands[%d].avx_bcast: %d", i, operand.avxBcast);
		if(operand.avxZeroOpmask)
			buf.writefln("\t\toperands[%d].avx_zero_opmask: TRUE", i);
		buf.writefln("\t\toperands[%d].size: %d", i, operand.size);
		if(operand.access)
			buf.writefln("\t\toperands[%u].access: %s", i, operand.access.accessToString);
	}
	auto regsAccess = cs.regsAccess(instr);
	if (!regsAccess.read.empty)
		buf.writefln("\tRegisters read: %s", regsAccess.read.map!(reg => cs.regName(reg)).join(" "));
	if (!regsAccess.write.empty)
		buf.writefln("\tRegisters modified: %s", regsAccess.write.map!(reg => cs.regName(reg)).join(" "));

	if (x86.eflags) {
		buf.writef("\tEFLAGS:");
		for(auto i = 0; i <= 45; i++){
			auto f = (1UL << i).to!EFlag;
			if (x86.eflags & f)
				buf.writef(" %s", f.to!string.toUpper);
		}
		buf.writefln("");
	}
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.x86);
		auto cs = new CapstoneX86(ModeFlags(platform.mode));
		cs.syntax = platform.syntax;
		cs.detail = true;
		
		auto res = cs.disasm(platform.code, 0x1000);
		assert(res.length > 0);

		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code:%s", platform.code.bytesToHex);
		buf.writefln("Disasm:");

		foreach(instr; res){
			buf.writefln("0x%x:\t%s\t%s\n", instr.address, instr.mnemonic, instr.opStr);
			buf.writeDetail(instr, cs);
		}
		buf.writefln("0x%x:", res[$-1].address + res[$-1].bytes.length);
		buf.writefln("");
	}

	const expected = import("x86.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}