module capstone.internal.x86;

import capstone.x86;

// Instruction operand
struct cs_x86_op {
		X86OpType type;	// operand type
		union {
			X86Register reg;	// register value for REG operand
			long imm;		// immediate value for IMM operand
			double fp;		// floating point value for FP operand
			X86OpMem mem;		// base/index/scale/disp value for MEM operand
		};

		// size of this operand (in bytes).
		ubyte size;

		// AVX broadcast type, or 0 if irrelevant
		X86AvxBroadcast avx_bcast;

		// AVX zero opmask {z}
		bool avx_zero_opmask;
}

// Instruction structure
struct cs_x86 {
	ubyte[4] prefix;
	ubyte[4] opcode;
	ubyte rex;
	ubyte addr_size;
	ubyte modrm;
	ubyte sib;
	int disp;

	X86Register sib_index;
	byte sib_scale;
	X86Register sib_base;

	X86SseCodeCondition sse_cc;
	X86AvxCodeCondition avx_cc;
	bool avx_sae;
	X86AvxRoundingMode avx_rm;

	ubyte op_count;
	cs_x86_op[8] operands;
}