module test.ppc;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum PPC_CODE = cast(ubyte[])"\x43\x20\x0c\x07\x41\x56\xff\x17\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21\x40\x82\x00\x14";
enum PPC_CODE2 = cast(ubyte[])"\x10\x60\x2a\x10\x10\x64\x28\x88\x7c\x4a\x5d\x0f";

enum platforms = [
	Platform(Arch.ppc, Mode.bigEndian, PPC_CODE, "PPC-64"),
	Platform(Arch.ppc, Mode.bigEndian + Mode.qpx, PPC_CODE2, "PPC-64 + QPX"),
];

void writeDetail(ref OutBuffer buf, in PpcInstruction instr){
	auto ppc = instr.detail; // = instr.detail.archSpecific;
	
	if(ppc.operands.length > 0)
		buf.writefln("\top_count: %d", ppc.operands.length);

	foreach(i, operand; ppc.operands){
		final switch(operand.type){
			case PpcOpType.invalid:
				break;
			case PpcOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, operand.reg.name);
				break;
			case PpcOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case PpcOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (operand.mem.base.id != PpcRegisterId.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, operand.mem.base.name);
				if (operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				break;
			case PpcOpType.crx:
				buf.writefln("\t\toperands[%u].type: CRX", i);
				buf.writefln("\t\t\toperands[%u].crx.scale: %d", i, operand.crx.scale);
				buf.writefln("\t\t\toperands[%u].crx.reg: %s", i, operand.crx.reg.name);
				buf.writefln("\t\t\toperands[%u].crx.cond: %s", i, operand.crx.cond);
				break;
		}
	}

	if (ppc.bc != PpcBc.invalid)
		buf.writefln("\tBranch code: %u", ppc.bc);
	if (ppc.bh != PpcBh.invalid)
		buf.writefln("\tBranch hint: %u", ppc.bh);
	if (ppc.updateCr0)
		buf.writefln("\tUpdate-CR0: True");
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.ppc);
		auto cs = new CapstonePpc(ModeFlags(platform.mode));
		cs.detail = true;
		
		buf.writefln("****************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code:%s", platform.code.bytesToHex);

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

	const expected = import("ppc.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}