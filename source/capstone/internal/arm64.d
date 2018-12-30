module capstone.internal.arm64;

import capstone.arm64;

// Instruction operand
struct cs_arm64_op {
	int vector_index;	// Vector Index for some vector operands (or -1 if irrelevant)
	Arm64Vas vas;		// Vector Arrangement Specifier
	Arm64Vess vess;		// Vector Element Size Specifier
	Arm64Shift shift;
	Arm64Extender ext;	// extender type of this operand
	Arm64OpType type;	// operand type

	// TODO: Remove padding workaround when compiler bug is sorted out (https://issues.dlang.org/show_bug.cgi?id=19516)
	static union U {
		Arm64Register reg;	// register value for REG operand
		long imm;		// immediate value, or index for C-IMM or IMM operand
		double fp;			// floating point value for FP operand
		Arm64OpMem mem;		// base/index/scale/disp value for MEM operand
		Arm64PState pstate;		// PState field of MSR instruction.
		uint sys;  // IC/DC/AT/TLBI operation (see arm64_ic_op, arm64_dc_op, arm64_at_op, arm64_tlbi_op)
		Arm64PrefetchOp prefetch;  // PRFM operation.
		Arm64BarrierOp barrier;  // Memory barrier operation (ISB/DMB/DSB instructions).
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
	Arm64Cc cc;	// conditional code for this insn
	bool update_flags;	// does this insn update flags?
	bool writeback;	// does this insn request writeback? 'True' means 'yes'

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;

	cs_arm64_op[8] operands; // operands for this instruction.
}