module test.tms320c64x;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;
import std.string: capitalize;

enum TMS320C64X_CODE = cast(ubyte[])"\x01\xac\x88\x40\x81\xac\x88\x43\x00\x00\x00\x00\x02\x90\x32\x96\x02\x80\x46\x9e\x05\x3c\x83\xe6\x0b\x0c\x8b\x24";

enum platforms = [
	Platform(Arch.tms320c64x, Mode.bigEndian, TMS320C64X_CODE, "TMS320C64x"),
];

void writeDetail(ref OutBuffer buf, in Tms320c64xInstruction instr){
	auto tms320c64x = instr.detail; // = instr.detail.archSpecific;
	
	if(tms320c64x.operands.length > 0)
		buf.writefln("\top_count: %d", tms320c64x.operands.length);

	foreach(i, op; tms320c64x.operands){
		final switch(op.type){
			case Tms320c64xOpType.invalid:
				break;
			case Tms320c64xOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, op.reg.name);
				break;
			case Tms320c64xOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, op.imm);
				break;
			case Tms320c64xOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (op.mem.base.id != Tms320c64xRegisterId.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, op.mem.base.name);

				buf.writefln("\t\t\toperands[%d].mem.disptype: %s", i, op.mem.disptype.to!string.capitalize);
				if(op.mem.disptype == Tms320c64xMemDisp.register)
					buf.writefln("\t\t\toperands[%d].mem.disp: %s", i, op.mem.disp.register.name);
				else
					buf.writefln("\t\t\toperands[%d].mem.disp: %d", i, op.mem.disp.constant);

				buf.writefln("\t\t\toperands[%d].mem.unit: %d", i, op.mem.unit);

				buf.writef("\t\t\toperands[%u].mem.direction: ", i);
				if(op.mem.direction == Tms320c64xMemDir.invalid)
					buf.writefln("Invalid");
				if(op.mem.direction == Tms320c64xMemDir.fw)
					buf.writefln("Forward");
				if(op.mem.direction == Tms320c64xMemDir.bw)
					buf.writefln("Backward");

				buf.writefln("\t\t\toperands[%d].mem.modify: %s", i, op.mem.modify.to!string.capitalize);
				buf.writefln("\t\t\toperands[%d].mem.scaled: %d", i, op.mem.scaled);
				break;
			case Tms320c64xOpType.regpair:
				buf.writefln("\t\toperands[%d].type: REGPAIR = %s:%s", i, op.regpair[1].name, op.regpair[0].name);
				break;
		}
	}

	buf.writef("\tFunctional unit: ");
	switch(tms320c64x.funit.unit) {
		case Tms320c64xFunitType.d:
			buf.writefln("D%d", tms320c64x.funit.side);
			break;
		case Tms320c64xFunitType.l:
			buf.writefln("L%d", tms320c64x.funit.side);
			break;
		case Tms320c64xFunitType.m:
			buf.writefln("M%d", tms320c64x.funit.side);
			break;
		case Tms320c64xFunitType.s:
			buf.writefln("S%d", tms320c64x.funit.side);
			break;
		case Tms320c64xFunitType.no:
			buf.writefln("No Functional Unit");
			break;
		default:
			buf.writefln("Unknown (Unit %u, Side %u)", tms320c64x.funit.unit, tms320c64x.funit.side);
			break;
	}
	if(tms320c64x.funit.crosspath == 1)
		buf.writefln("\tCrosspath: 1");

	if(tms320c64x.condition.reg.id != Tms320c64xRegisterId.invalid)
		buf.writefln("\tCondition: [%c%s]", (tms320c64x.condition.zero == 1) ? '!' : ' ', tms320c64x.condition.reg.name);
	buf.writefln("\tParallel: %s", (tms320c64x.parallel == 1) ? "true" : "false");

	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.tms320c64x);
		auto cs = new CapstoneTms320c64x(ModeFlags(platform.mode));
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

	const expected = import("tms320c64x.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}