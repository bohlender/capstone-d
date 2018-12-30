module capstone.internal.mips;

import capstone.mips;

// Instruction operand
struct cs_mips_op {
	MipsOpType type;		// operand type
	union {
		MipsRegister reg;	// register value for REG operand
		long imm;			// immediate value for IMM operand
		MipsOpMem mem;		// base/index/scale/disp value for MEM operand
	}
}

// Instruction structure
struct cs_mips {
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_mips_op[10] operands; // operands for this instruction.
}