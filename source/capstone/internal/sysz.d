module capstone.internal.sysz;

alias sysz_cc = int;
alias sysz_op_type = int;
alias sysz_reg = int;
alias sysz_insn = int;
alias sysz_insn_group = int;

struct sysz_op_mem {
	ubyte base;	  // base register
	ubyte index;  // index register
	ulong length; // BDLAddr operand
	long disp;	  // displacement/offset value
}

// Instruction operand
struct cs_sysz_op {
	sysz_op_type type;   // operand type
	union {
		sysz_reg reg; 	 // register value for REG operand
		long imm;	   	 // immediate value for IMM operand
		sysz_op_mem mem; // base/disp value for MEM operand
	}
}

// Instruction structure
struct cs_sysz {
	sysz_cc cc;	// Code condition
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_sysz_op[6] operands; // operands for this instruction.
}