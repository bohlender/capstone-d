module capstone.internal.m680x;

alias m680x_reg = int;
alias m680x_op_type = int;
alias m680x_group_type = int;
alias m680x_insn = int;

// Instruction's operand referring to indexed addressing
struct m680x_op_idx {
	m680x_reg base_reg;	  // base register (or M680X_REG_INVALID if irrelevant)
	m680x_reg offset_reg; // offset register (or M680X_REG_INVALID if irrelevant)
	short offset;		  // 5-,8- or 16-bit offset. See also offset_bits.
	ushort offset_addr;   // = offset addr. if base_reg == M680X_REG_PC.
						  // calculated as offset + PC
	ubyte offset_bits;    // offset width in bits for indexed addressing
	byte inc_dec;		  // inc. or dec. value:
					      //    0: no inc-/decrement
					      //    1 .. 8: increment by 1 .. 8
					      //    -1 .. -8: decrement by 1 .. 8
					      // if flag M680X_IDX_POST_INC_DEC set it is post
					      // inc-/decrement otherwise pre inc-/decrement
	ubyte flags;          // 8-bit flags (see above)
}

// Instruction's memory operand referring to relative addressing (Bcc/LBcc)
struct m680x_op_rel {
	ushort address;	// The absolute address.
					// calculated as PC + offset. PC is the first
					// address after the instruction.
	short offset;	// the offset/displacement value
}

// Instruction's operand referring to extended addressing
struct m680x_op_ext {
	ushort address; // The absolute address
	bool indirect;  // true if extended indirect addressing
}

// Instruction operand
struct cs_m680x_op {
	m680x_op_type type;
	union {
		int imm;			// immediate value for IMM operand
		m680x_reg reg;		// register value for REG operand
		m680x_op_idx idx;	// Indexed addressing operand
		m680x_op_rel rel;	// Relative address. operand (Bcc/LBcc)
		m680x_op_ext ext;	// Extended address
		ubyte direct_addr;	// Direct address (lower 8-bit)
		ubyte const_val;	// constant value (bit index, page nr.)
	};
	ubyte size;			///< size of this operand (in bytes)
	/// How is this operand accessed? (READ, WRITE or READ|WRITE)
	/// This field is combined of cs_ac_type.
	/// NOTE: this field is irrelevant if engine is compiled in DIET 
	ubyte access;
}

// The M680X instruction and it's operands
struct cs_m680x {
	ubyte flags;			 // See: M680X instruction flags
	ubyte op_count;			 // number of operands for the instruction or 0
	cs_m680x_op[9] operands; // operands for this insn.
}