module capstone.internal.x86;

alias x86_reg = int;
alias x86_op_type = int;
alias x86_avx_bcast = int;
alias x86_xop_cc = int;
alias x86_sse_cc = int;
alias x86_avx_cc = int;
alias x86_avx_rm = int;

struct x86_op_mem {
	x86_reg segment; // segment register (or X86_REG_INVALID if irrelevant)
	x86_reg base;	 // base register (or X86_REG_INVALID if irrelevant)
	x86_reg index;	 // index register (or X86_REG_INVALID if irrelevant)
	int scale;		 // scale for index register
	long disp;	 // displacement value
}

// Instruction operand
struct cs_x86_op {
		x86_op_type type;	// operand type
		union {
			x86_reg reg;	// register value for REG operand
			long imm;		// immediate value for IMM operand
			x86_op_mem mem;		// base/index/scale/disp value for MEM operand
		};

		// size of this operand (in bytes).
		ubyte size;

		/// How is this operand accessed? (READ, WRITE or READ|WRITE)
		/// This field is combined of cs_ac_type.
		/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
		ubyte access;

		// AVX broadcast type, or 0 if irrelevant
		x86_avx_bcast avx_bcast;

		// AVX zero opmask {z}
		bool avx_zero_opmask;
}

struct cs_x86_encoding {
	/// ModR/M offset, or 0 when irrelevant
	ubyte modrm_offset;

	/// Displacement offset, or 0 when irrelevant.
	ubyte disp_offset;
	ubyte disp_size;

	/// Immediate offset, or 0 when irrelevant.
	ubyte imm_offset;
	ubyte imm_size;
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

	x86_reg sib_index;
	byte sib_scale;
	x86_reg sib_base;

	x86_xop_cc xop_cc;
	x86_sse_cc sse_cc;
	x86_avx_cc avx_cc;
	bool avx_sae;
	x86_avx_rm avx_rm;

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

	cs_x86_encoding encoding; ///< encoding information
}