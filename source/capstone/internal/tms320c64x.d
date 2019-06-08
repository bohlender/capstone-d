module capstone.internal.tms320c64x;

alias tms320c64x_op_type = int;
alias tms320c64x_mem_disp = int;
alias tms320c64x_mem_dir = int;
alias tms320c64x_mem_mod = int;
alias tms320c64x_reg = int;
alias tms320c64x_insn = int;
alias tms320c64x_insn_group = int;
alias tms320c64x_funit = int;

struct tms320c64x_op_mem {
	uint base;	// base register
	uint disp;	// displacement/offset value
	uint unit;	// unit of base and offset register
	uint scaled;	// offset scaled
	uint disptype;	// displacement type
	uint direction;	// direction
	uint modify;	// modification
}

struct cs_tms320c64x_op {
	tms320c64x_op_type type; // operand type
	union {
		uint reg;	// register value for REG operand or first register for REGPAIR operand
		int imm;	// immediate value for IMM operand
		tms320c64x_op_mem mem; // base/disp value for MEM operand
	}
}

struct cs_tms320c64x_condition {
	uint reg;
	uint zero;
}

struct cs_tms320c64x_funit {
	uint unit;
	uint side;
	uint crosspath;
}

struct cs_tms320c64x {
	ubyte op_count;
	cs_tms320c64x_op[8] operands; // operands for this instruction.
	cs_tms320c64x_condition condition;
	cs_tms320c64x_funit funit;
	uint parallel;
}