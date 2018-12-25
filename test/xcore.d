module test.xcore;

import std.outbuffer;
import std.conv: to;

import capstone;
import test.utils;

enum XCORE_CODE = cast(ubyte[])"\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10\x09\xfd\xec\xa7";

enum platforms = [
	Platform(Arch.xcore, Mode.bigEndian, XCORE_CODE, "XCore"),
];

void writeDetail(ref OutBuffer buf, in InstructionXCore instr, in CapstoneXCore cs){
	assert(!instr.detail.isNull);
	auto xcore = instr.detail; // = instr.detail.archSpecific;
	
	if(xcore.operands.length > 0)
		buf.writefln("\top_count: %d", xcore.operands.length);
	foreach(i, operand; xcore.operands){
		final switch(operand.type){
			case XCoreOpType.invalid:
				break;
			case XCoreOpType.reg:
				buf.writefln("\t\toperands[%d].type: REG = %s", i, cs.regName(operand.reg));
				break;
			case XCoreOpType.imm:
				buf.writefln("\t\toperands[%d].type: IMM = 0x%x", i, operand.imm);
				break;
			case XCoreOpType.mem:
				buf.writefln("\t\toperands[%d].type: MEM", i);
				if (operand.mem.base != XCoreRegister.invalid)
					buf.writefln("\t\t\toperands[%d].mem.base: REG = %s", i, cs.regName(operand.mem.base));
				if (operand.mem.index != XCoreRegister.invalid)
					buf.writefln("\t\t\toperands[%u].mem.index: REG = %s", i, cs.regName(operand.mem.index));
				if (operand.mem.disp != 0)
					buf.writefln("\t\t\toperands[%d].mem.disp: 0x%x", i, operand.mem.disp);
				if (operand.mem.direct != 1)
					buf.writefln("\t\t\toperands[%u].mem.direct: -1", i);
				break;
		}
	}
	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.xcore);
		auto cs = new CapstoneXCore(ModeFlags(platform.mode));
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

	const expected = import("xcore.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}