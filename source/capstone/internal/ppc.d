module capstone.internal.ppc;

alias ppc_bc = int;
alias ppc_bh = int;
alias ppc_op_type = int;
alias ppc_reg = int;
alias ppc_insn = int;
alias ppc_insn_group = int;

struct ppc_op_mem {
	ppc_reg base;	// base register
	int disp;		// displacement/offset value
}

struct ppc_op_crx {
	uint scale;
	ppc_reg reg;
	ppc_bc cond;
}

// Instruction operand
struct cs_ppc_op {
	ppc_op_type type;	// operand type
	union {
		ppc_reg reg;	// register value for REG operand
		long imm;		// immediate value for IMM operand
		ppc_op_mem mem;	// base/disp value for MEM operand
		ppc_op_crx crx;	// operand with condition register
	}
}

// Instruction structure
struct cs_ppc {
	// branch code for branch instructions
	ppc_bc bc;

	// branch hint for branch instructions
	ppc_bh bh;

	// if update_cr0 = True, then this 'dot' insn updates CR0
	bool update_cr0;

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_ppc_op[8] operands; // operands for this instruction.
}