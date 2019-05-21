module capstone.internal.sparc;

alias sparc_cc = int;
alias sparc_hint = int;
alias sparc_op_type = int;
alias sparc_reg = int;
alias sparc_insn = int;
alias sparc_insn_group = int;

struct sparc_op_mem {
	ubyte base;	  // base register, can be safely interpreted as a value of type `sparc_reg`, but it is only one byte wide
	ubyte index;  // index register, same conditions apply here
	int disp;	  // displacement/offset value
}

// Instruction operand
struct cs_sparc_op {
	sparc_op_type type;	// operand type
	union {
		sparc_reg reg; // register value for REG operand
		long imm;		   // immediate value for IMM operand
		sparc_op_mem mem;  // base/disp value for MEM operand
	}
}

// Instruction structure
struct cs_sparc {
	sparc_cc cc;	// code condition for this insn
	sparc_hint hint;	// branch hint: encoding as bitwise OR of sparc_hint.
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_sparc_op[4] operands; // operands for this instruction.
}