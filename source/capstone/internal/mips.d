module capstone.internal.mips;

alias mips_op_type = int;
alias mips_reg = int;
alias mips_insn = int;
alias mips_insn_group = int;

/// Instruction's operand referring to memory
/// This is associated with MIPS_OP_MEM operand type above
struct mips_op_mem {
	mips_reg base;	// base register
	long disp;	// displacement/offset value
}

// Instruction operand
struct cs_mips_op {
	mips_op_type type;	// operand type
	union {
		mips_reg reg;	// register value for REG operand
		long imm;		// immediate value for IMM operand
		mips_op_mem mem;// base/index/scale/disp value for MEM operand
	}
}

// Instruction structure
struct cs_mips {
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_mips_op[10] operands; // operands for this instruction.
}