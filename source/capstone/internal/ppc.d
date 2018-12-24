module capstone.internal.ppc;

import capstone.ppc;

// Instruction operand
struct cs_ppc_op {
	PpcOpType type;	// operand type
	union {
		PpcRegister reg; // register value for REG operand
		uint imm;		 // immediate value for IMM operand
		PpcOpMem mem;	 // base/disp value for MEM operand
		PpcOpCrx crx;	 // operand with condition register
	};
}

// Instruction structure
struct cs_ppc {
	// branch code for branch instructions
	PpcBc bc;

	// branch hint for branch instructions
	PpcBh bh;

	// if update_cr0 = True, then this 'dot' insn updates CR0
	bool update_cr0;

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_ppc_op[8] operands; // operands for this instruction.
}