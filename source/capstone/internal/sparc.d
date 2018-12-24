module capstone.internal.sparc;

import capstone.sparc;

struct sparc_op_mem {
	ubyte base;	  // base register, can be safely interpreted as a value of type `sparc_reg`, but it is only one byte wide
	ubyte index;  // index register, same conditions apply here
	int disp;	  // displacement/offset value
}

// Instruction operand
struct cs_sparc_op {
	SparcOpType type;	// operand type
	union {
		SparcRegister reg; // register value for REG operand
		int imm;		   // immediate value for IMM operand
		sparc_op_mem mem;  // base/disp value for MEM operand
	}
}

// Instruction structure
struct cs_sparc {
	SparcCc cc;	// code condition for this insn
	SparcHint hint;	// branch hint: encoding as bitwise OR of sparc_hint.
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_sparc_op[4] operands; // operands for this instruction.
}