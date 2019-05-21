module capstone.internal.xcore;

alias xcore_op_type = int;
alias xcore_reg = int;
alias xcore_insn = int;
alias xcore_insn_group = int;

// Instruction's operand referring to memory
// This is associated with XCORE_OP_MEM operand type above
struct xcore_op_mem {
	ubyte base;	 // base register
	ubyte index; // index register
	int disp;	 // displacement/offset value
	int direct;	 // +1: forward, -1: backward
}

// Instruction operand
struct cs_xcore_op {
	xcore_op_type type;	   // operand type
	union {
		xcore_reg reg; // register value for REG operand
		int imm;		   // immediate value for IMM operand
		xcore_op_mem mem;  // base/disp value for MEM operand
	}
}

// Instruction structure
struct cs_xcore {
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_xcore_op[8] operands; // operands for this instruction.
}