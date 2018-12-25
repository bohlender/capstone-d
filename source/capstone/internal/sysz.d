module capstone.internal.sysz;

import capstone.sysz;

struct sysz_op_mem {
	ubyte base;	  // base register
	ubyte index;  // index register
	ulong length; // BDLAddr operand
	long disp;	  // displacement/offset value
}

// Instruction operand
struct cs_sysz_op {
	SyszOpType type;   // operand type
	union {
		SyszRegister reg; // register value for REG operand
		long imm;	   	  // immediate value for IMM operand
		sysz_op_mem mem;  // base/disp value for MEM operand
	}
}

// Instruction structure
struct cs_sysz {
	SyszCc cc;		// Code condition
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_sysz_op[6] operands; // operands for this instruction.
}