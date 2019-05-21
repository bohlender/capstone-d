module capstone.internal.arm;

alias arm_reg = int;
alias arm_shifter = int;
alias arm_op_type = int;
alias arm_setend_type = int;
alias arm_vectordata_type = int;
alias arm_cpsmode_type = int;
alias arm_cpsflag_type = int;
alias arm_cc = int;
alias arm_mem_barrier = int;

struct arm_op_mem {
	arm_reg base;	///< base register
	arm_reg index;	///< index register
	int scale;	///< scale for index register (can be 1, or -1)
	int disp;	///< displacement/offset value
	/// left-shift on index register, or 0 if irrelevant
	/// NOTE: this value can also be fetched via operand.shift.value
	int lshift;
}

// Instruction operand
struct cs_arm_op {
	int vector_index;	// Vector Index for some vector operands (or -1 if irrelevant)

	static struct Shift{
		arm_shifter type;
		uint value;
	};
	Shift shift;
	arm_op_type type;	// operand type
	
	// TODO: Remove padding workaround when compiler bug is sorted out (https://issues.dlang.org/show_bug.cgi?id=19516)
	static union U {
		arm_reg reg;	// register value for REG/SYSREG operand
		int imm;			// immediate value for C-IMM, P-IMM or IMM operand
		double fp;			// floating point value for FP operand
		arm_op_mem mem;		// base/index/scale/disp value for MEM operand
		arm_setend_type setend; // SETEND instruction's operand type
	};
	U u;
	alias u this;

	// in some instructions, an operand can be subtracted or added to
	// the base register,
	bool subtracted; // if TRUE, this operand is subtracted. otherwise, it is added.

	// How is this operand accessed? (READ, WRITE or READ|WRITE)
	// This field is combined of cs_ac_type.
	// NOTE: this field is irrelevant if engine is compiled in DIET mode.
	ubyte access;

	// Neon lane index for NEON instructions (or -1 if irrelevant)
	byte neon_lane;
}

// Instruction structure
struct cs_arm {
	bool usermode;	// User-mode registers to be loaded (for LDM/STM instructions)
	int vector_size; 	// Scalar size for vector instructions
	arm_vectordata_type vector_data; // Data type for elements of vector instructions
	arm_cpsmode_type cps_mode;	// CPS mode for CPS instruction
	arm_cpsflag_type cps_flag;	// CPS mode for CPS instruction
	arm_cc cc;			// conditional code for this insn
	bool update_flags;	// does this insn update flags?
	bool writeback;		// does this insn write-back?
	arm_mem_barrier mem_barrier;	// Option for some memory barrier instructions

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	ubyte op_count;
	cs_arm_op[36] operands;	// operands for this instruction.
}