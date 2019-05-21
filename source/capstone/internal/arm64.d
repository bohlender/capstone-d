module capstone.internal.arm64;

alias arm64_shifter = int;
alias arm64_extender = int;
alias arm64_cc = int;
alias arm64_sysreg = int;
alias arm64_msr_reg = int;
alias arm64_pstate = int;
alias arm64_vas = int;
alias arm64_vess = int;
alias arm64_barrier_op = int;
alias arm64_op_type = int;
alias arm64_tlbi_op = int;
alias arm64_at_op = int;
alias arm64_dc_op = int;
alias arm64_ic_op = int;
alias arm64_prefetch_op = int;
alias arm64_reg = int;
alias arm64_insn = int;
alias arm64_insn_group = int;

struct arm64_op_mem {
	arm64_reg base;	///< base register
	arm64_reg index;	///< index register
	int disp;	///< displacement/offset value
}

// Instruction operand
struct cs_arm64_op {
	int vector_index;	// Vector Index for some vector operands (or -1 if irrelevant)
	arm64_vas vas;		// Vector Arrangement Specifier
	arm64_vess vess;	// Vector Element Size Specifier

	static struct Shift{
		arm64_shifter type;
		uint value;
	};
	Shift shift;
	arm64_extender ext;	// extender type of this operand
	arm64_op_type type;	// operand type

	// TODO: Remove padding workaround when compiler bug is sorted out (https://issues.dlang.org/show_bug.cgi?id=19516)
	static union U {
		arm64_reg reg;				// register value for REG operand
		long imm;					// immediate value, or index for C-IMM or IMM operand
		double fp;					// floating point value for FP operand
		arm64_op_mem mem;			// base/index/scale/disp value for MEM operand
		arm64_pstate pstate;		// PState field of MSR instruction.
		uint sys;  					// IC/DC/AT/TLBI operation (see arm64_ic_op, arm64_dc_op, arm64_at_op, arm64_tlbi_op)
		arm64_prefetch_op prefetch; // PRFM operation.
		arm64_barrier_op barrier;  	// Memory barrier operation (ISB/DMB/DSB instructions).
	};
	U u;
	alias u this;

	// How is this operand accessed? (READ, WRITE or READ|WRITE)
	// This field is combined of cs_ac_type.
	// NOTE: this field is irrelevant if engine is compiled in DIET mode.
	ubyte access;
}

// Instruction structure
struct cs_arm64 {
	arm64_cc cc;	// conditional code for this insn
	bool update_flags;	// does this insn update flags?
	bool writeback;	// does this insn request writeback? 'True' means 'yes'

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;

	cs_arm64_op[8] operands; // operands for this instruction.
}