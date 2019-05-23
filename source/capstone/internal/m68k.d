module capstone.internal.m68k;

alias m68k_reg = int;
alias m68k_address_mode = int;
alias m68k_op_type = int;
alias m68k_op_br_disp_size = int;
alias m68k_cpu_size = int;
alias m68k_fpu_size = int;
alias m68k_size_type = int;
alias m68k_insn = int;
alias m68k_group_type = int;

struct m68k_op_mem {
    m68k_reg base_reg;      // base register (or M68K_REG_INVALID if irrelevant)
    m68k_reg index_reg;     // index register (or M68K_REG_INVALID if irrelevant)
    m68k_reg in_base_reg;   // indirect base register (or M68K_REG_INVALID if irrelevant)
    uint in_disp; 	   		// indirect displacement
    uint out_disp;    		// other displacement
    short disp;	      		// displacement value
    ubyte scale;	        // scale for index register
    ubyte bitfield;         // set to true if the two values below should be used
    ubyte width;	        // used for bf* instructions
    ubyte offset;	        // used for bf* instructions
    ubyte index_size;       // 0 = w, 1 = l
}

struct m68k_op_br_disp {
	int disp;	        // displacement value
	ubyte disp_size;	// Size from m68k_op_br_disp_size type above
}

struct cs_m68k_reg_pair {
	m68k_reg reg_0;
	m68k_reg reg_1;
}

// Instruction operand
struct cs_m68k_op {
	union {
		ulong imm;           // immediate value for IMM operand
		double dimm; 	     // double imm
		float simm; 	     // float imm
		m68k_reg reg;	     // register value for REG operand
		cs_m68k_reg_pair reg_pair; // register pair in one operand
	}

	m68k_op_mem mem; 	     // data when operand is targeting memory
	m68k_op_br_disp br_disp; // data when operand is a branch displacement
	uint register_bits;      // register bits for movem etc. (always in d0-d7, a0-a7, fp0 - fp7 order)
	m68k_op_type type;
	m68k_address_mode address_mode;	// M68K addressing mode for this op
}

// Operation size of the current instruction (NOT the actually size of instruction)
struct m68k_op_size {
	m68k_size_type type;
	union {
		m68k_cpu_size cpu_size;
		m68k_fpu_size fpu_size;
	}
}

// The M68K instruction and it's operands
struct cs_m68k {
	// Number of operands of this instruction or 0 when instruction has no operand.
	cs_m68k_op[4] operands; // operands for this instruction.
	m68k_op_size op_size;	// size of data operand works on in bytes (.b, .w, .l, etc)
	ubyte op_count;       // number of operands for the instruction
}