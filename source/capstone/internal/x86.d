module capstone.internal.x86;

import capstone.x86;

// Instruction operand
struct cs_x86_op {
		X86OpType type;	// operand type
		union {
			X86Register reg;	// register value for REG operand
			long imm;		// immediate value for IMM operand
			X86OpMem mem;		// base/index/scale/disp value for MEM operand
		};

		// size of this operand (in bytes).
		ubyte size;

		/// How is this operand accessed? (READ, WRITE or READ|WRITE)
		/// This field is combined of cs_ac_type.
		/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
		ubyte access;

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
	long disp;

	X86Register sib_index;
	byte sib_scale;
	X86Register sib_base;

	X86XopCc xop_cc;
	X86SseCodeCondition sse_cc;
	X86AvxCodeCondition avx_cc;
	bool avx_sae;
	X86AvxRoundingMode avx_rm;

	// TODO: Remove padding workaround when compiler bug is sorted out (https://issues.dlang.org/show_bug.cgi?id=19516)
	static union U {
		/// EFLAGS updated by this instruction.
		/// This can be formed from OR combination of X86_EFLAGS_* symbols in x86.h
		ulong eflags;
		/// FPU_FLAGS updated by this instruction.
		/// This can be formed from OR combination of X86_FPU_FLAGS_* symbols in x86.h
		ulong fpu_flags;
	}
	U u;
	alias u this;

	ubyte op_count;
	cs_x86_op[8] operands;

	X86Encoding encoding; ///< encoding information
}