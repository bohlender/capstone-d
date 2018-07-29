module capstone.internal.arm;

import capstone.arm;

// Instruction operand
struct cs_arm_op {
	int vector_index;	// Vector Index for some vector operands (or -1 if irrelevant)
	ArmShift shift;
	ArmOpType type;	// operand type
	union {
		ArmRegister reg;	// register value for REG/SYSREG operand
		int imm;			// immediate value for C-IMM, P-IMM or IMM operand
		double fp;			// floating point value for FP operand
		ArmOpMem mem;		// base/index/scale/disp value for MEM operand
		ArmSetendType setend; // SETEND instruction's operand type
	};
	// in some instructions, an operand can be subtracted or added to
	// the base register,
	bool subtracted; // if TRUE, this operand is subtracted. otherwise, it is added.
}

// Instruction structure
struct cs_arm {
	bool usermode;	// User-mode registers to be loaded (for LDM/STM instructions)
	int vector_size; 	// Scalar size for vector instructions
	ArmVectordataType vector_data; // Data type for elements of vector instructions
	ArmCpsmodeType cps_mode;	// CPS mode for CPS instruction
	ArmCpsflagType cps_flag;	// CPS mode for CPS instruction
	ArmCc cc;			// conditional code for this insn
	bool update_flags;	// does this insn update flags?
	bool writeback;		// does this insn write-back?
	ArmMemBarrier mem_barrier;	// Option for some memory barrier instructions

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;

	cs_arm_op[36] operands;	// operands for this instruction.
}