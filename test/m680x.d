module test.m680x;

import std.outbuffer;
import std.format: format;
import std.conv: to;
import std.math: abs;

import capstone;
import test.utils;

enum M6800_CODE = cast(ubyte[])"\x01\x09\x36\x64\x7f\x74\x10\x00\x90\x10\xA4\x10\xb6\x10\x00\x39";
enum M6801_CODE = cast(ubyte[])"\x04\x05\x3c\x3d\x38\x93\x10\xec\x10\xed\x10\x39";
enum M6805_CODE = cast(ubyte[])"\x04\x7f\x00\x17\x22\x28\x00\x2e\x00\x40\x42\x5a\x70\x8e\x97\x9c\xa0\x15\xad\x00\xc3\x10\x00\xda\x12\x34\xe5\x7f\xfe";
enum M6808_CODE = cast(ubyte[])"\x31\x22\x00\x35\x22\x45\x10\x00\x4b\x00\x51\x10\x52\x5e\x22\x62\x65\x12\x34\x72\x84\x85\x86\x87\x8a\x8b\x8c\x94\x95\xa7\x10\xaf\x10\x9e\x60\x7f\x9e\x6b\x7f\x00\x9e\xd6\x10\x00\x9e\xe6\x7f";
enum HCS08_CODE = cast(ubyte[])"\x32\x10\x00\x9e\xae\x9e\xce\x7f\x9e\xbe\x10\x00\x9e\xfe\x7f\x3e\x10\x00\x9e\xf3\x7f\x96\x10\x00\x9e\xff\x7f\x82";
enum M6811_CODE = cast(ubyte[])"\x02\x03\x12\x7f\x10\x00\x13\x99\x08\x00\x14\x7f\x02\x15\x7f\x01\x1e\x7f\x20\x00\x8f\xcf\x18\x08\x18\x30\x18\x3c\x18\x67\x18\x8c\x10\x00\x18\x8f\x18\xce\x10\x00\x18\xff\x10\x00\x1a\xa3\x7f\x1a\xac\x1a\xee\x7f\x1a\xef\x7f\xcd\xac\x7f";
enum CPU12_CODE = cast(ubyte[])"\x00\x04\x01\x00\x0c\x00\x80\x0e\x00\x80\x00\x11\x1e\x10\x00\x80\x00\x3b\x4a\x10\x00\x04\x4b\x01\x04\x4f\x7f\x80\x00\x8f\x10\x00\xb7\x52\xb7\xb1\xa6\x67\xa6\xfe\xa6\xf7\x18\x02\xe2\x30\x39\xe2\x10\x00\x18\x0c\x30\x39\x10\x00\x18\x11\x18\x12\x10\x00\x18\x19\x00\x18\x1e\x00\x18\x3e\x18\x3f\x00";
enum HD6301_CODE = cast(ubyte[])"\x6b\x10\x00\x71\x10\x00\x72\x10\x10\x39";
enum M6809_CODE = cast(ubyte[])"\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00";
enum HD6309_CODE = cast(ubyte[])"\x01\x10\x10\x62\x10\x10\x7b\x10\x10\x00\xcd\x49\x96\x02\xd2\x10\x30\x23\x10\x38\x10\x3b\x10\x53\x10\x5d\x11\x30\x43\x10\x11\x37\x25\x10\x11\x38\x12\x11\x39\x23\x11\x3b\x34\x11\x8e\x10\x00\x11\xaf\x10\x11\xab\x10\x11\xf6\x80\x00";

enum platforms = [
	Platform(Arch.m680x, Mode.m680x_6301, HD6301_CODE, "M680X_HD6301"),
	Platform(Arch.m680x, Mode.m680x_6309, HD6309_CODE, "M680X_HD6309"),
	Platform(Arch.m680x, Mode.m680x_6800, M6800_CODE, "M680X_M6800"),
	Platform(Arch.m680x, Mode.m680x_6801, M6801_CODE, "M680X_M6801"),
	Platform(Arch.m680x, Mode.m680x_6805, M6805_CODE, "M680X_M68HC05"),
	Platform(Arch.m680x, Mode.m680x_6808, M6808_CODE, "M680X_M68HC08"),
	Platform(Arch.m680x, Mode.m680x_6809, M6809_CODE, "M680X_M6809"),
	Platform(Arch.m680x, Mode.m680x_6811, M6811_CODE, "M680X_M68HC11"),
	Platform(Arch.m680x, Mode.m680x_cpu12, CPU12_CODE, "M680X_CPU12"),
	Platform(Arch.m680x, Mode.m680x_hcs08, HCS08_CODE, "M680X_HCS08"),
];

void writeDetail(ref OutBuffer buf, in M680xInstruction instr){
	auto m680x = instr.detail; // = instr.detail.archSpecific;
	
	if(m680x.operands.length > 0)
		buf.writefln("\top_count: %d", m680x.operands.length);

	foreach(i, op; m680x.operands){
		switch(op.type){
			case M680xOpType.register:
				auto comment = "";
				if((i==0 && (m680x.flags & M680xInstructionFlag.firstOpInMnem)) || (i==1 && (m680x.flags & M680xInstructionFlag.secondOpInMnem)))
					comment = " (in mnemonic)";
				buf.writefln("\t\toperands[%d].type: REGISTER = %s%s", i, op.reg.name, comment);
				break;
			case M680xOpType.constant:
				buf.writefln("\t\toperands[%d].type: CONSTANT = %d", i, op.constVal);
				break;
			case M680xOpType.immediate:
				buf.writefln("\t\toperands[%d].type: IMMEDIATE = #%d", i, op.imm);
				break;
			case M680xOpType.direct:
				buf.writefln("\t\toperands[%d].type: DIRECT = 0x%02X", i, op.directAddr);
				break;
			case M680xOpType.extended:
				buf.writefln("\t\toperands[%d].type: EXTENDED %s = 0x%04X", i, op.ext.indirect ? "INDIRECT" : "", op.ext.address);
				break;
			case M680xOpType.relative:
				buf.writefln("\t\toperands[%d].type: RELATIVE = 0x%04X", i, op.rel.address);
				break;
			case M680xOpType.indexed:
				buf.writefln("\t\toperands[%d].type: INDEXED%s", i, (op.idx.flags & M680xFlag.indirect) ? " INDIRECT" : "");

				if(op.idx.baseReg.id != M680xRegisterId.invalid)
					buf.writefln("\t\t\tbase register: %s",	op.idx.baseReg.name);
				if(op.idx.offsetReg.id != M680xRegisterId.invalid)
					buf.writefln("\t\t\toffset register: %s", op.idx.offsetReg.name);

				if((op.idx.offsetBits != 0) && (op.idx.offsetReg.id == M680xRegisterId.invalid) && !op.idx.incDec) {
					buf.writefln("\t\t\toffset: %d", op.idx.offset);

					if(op.idx.baseReg.id == M680xRegisterId.pc)
						buf.writefln("\t\t\toffset address: 0x%X", op.idx.offsetAddr);
					buf.writefln("\t\t\toffset bits: %d", op.idx.offsetBits);
				}

				if(op.idx.incDec) {
					auto postPre = (op.idx.flags & M680xFlag.postIncDec) ? "post" : "pre";
					auto incDec = (op.idx.incDec > 0) ? "increment" : "decrement";

					buf.writefln("\t\t\t%s %s: %d", postPre, incDec, abs(op.idx.incDec));
				}
				break;
			default:
				break;
		}

		if(op.size != 0)
			buf.writefln("\t\t\tsize: %d", op.size);
		if(op.access)
			buf.writefln("\t\t\taccess: %s", op.access.accessToString);
	}

	auto read = m680x.regsRead;
	if(read.length > 0) {
		buf.writef("\tRegisters read:");
		foreach(reg; read)
			buf.writef(" %s", reg.name);
		buf.writefln("");
	}

	auto modified = m680x.regsWrite;
	if(modified.length > 0) {
		buf.writef("\tRegisters modified:");
		foreach(reg; modified)
			buf.writef(" %s", reg.name);
		buf.writefln("");
	}

	if(m680x.groups.length > 0)
		buf.writefln("\tgroups_count: %d", m680x.groups.length);

	buf.writefln("");
}

unittest{
	auto buf = new OutBuffer;
	foreach(platform; platforms) {
		assert(platform.arch == Arch.m680x);
		auto cs = new CapstoneM680x(ModeFlags(platform.mode));
		cs.detail = true;
		
		buf.writefln("********************");
		buf.writefln("Platform: %s", platform.comment);
		buf.writefln("Code: %s", platform.code.bytesToHex(true, true));

		auto res = cs.disasm(platform.code, 0x1000);
		if(res.length > 0){
			buf.writefln("Disasm:");
			foreach(instr; res) {
				auto spaces = "%.*s".format(1 + (5-instr.bytes.length.to!int)*2, "         "); // weird spacing taken from original test
				buf.writefln("0x%04X: %s%s%-5s %s", instr.address, instr.bytes.bytesToHex(false,true,false), spaces, instr.mnemonic, instr.opStr);
				buf.writeDetail(instr);
			}
		}else{
			buf.writefln("ERROR: Failed to disasm given code!");
		}
		// buf.writefln("");
	}

	const expected = import("m680x.expected");
	const actual = buf.toString;

	assert(expected == actual, expectationMismatch(expected, actual));
}