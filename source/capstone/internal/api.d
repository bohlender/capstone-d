module capstone.internal.api;

import capstone.internal;

// Capstone API version
enum uint CS_API_MAJOR = 3;
enum uint CS_API_MINOR = 0;

// Runtime option for the disassembled engine
enum cs_opt_type {
	CS_OPT_SYNTAX = 1,	// Assembly output syntax
	CS_OPT_DETAIL,	// Break down instruction structure into details
	CS_OPT_MODE,	// Change engine's mode at run-time
	CS_OPT_MEM,	// User-defined dynamic memory related functions
	CS_OPT_SKIPDATA, // Skip data when disassembling. Then engine is in SKIPDATA mode.
	CS_OPT_SKIPDATA_SETUP // Setup user-defined function for SKIPDATA option
}

// Runtime option value (associated with option type above)
enum cs_opt_value {
	CS_OPT_OFF = 0,  // Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA.
	CS_OPT_ON = 3, // Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
	CS_OPT_SYNTAX_DEFAULT = 0, // Default asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_INTEL, // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_ATT,   // X86 ATT asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_NOREGNAME // Prints register name with only number (CS_OPT_SYNTAX)
}

alias cs_skipdata_cb_t = extern(C) size_t function(const(ubyte)* code,
	size_t code_size,
	size_t offset,
	void* user_data);

// User-customized setup for SKIPDATA option
struct cs_opt_skipdata {
	// Capstone considers data to skip as special "instructions".
	// User can specify the string for this instruction's "mnemonic" here.
	// By default (if @mnemonic is NULL), Capstone use ".byte".
	const char* mnemonic;

	// User-defined callback function to be called when Capstone hits data.
	// If the returned value from this callback is positive (>0), Capstone
	// will skip exactly that number of bytes & continue. Otherwise, if
	// the callback returns 0, Capstone stops disassembling and returns
	// immediately from cs_disasm()
	// NOTE: if this callback pointer is NULL, Capstone would skip a number
	// of bytes depending on architectures, as following:
	// Arm:     2 bytes (Thumb mode) or 4 bytes.
	// Arm64:   4 bytes.
	// Mips:    4 bytes.
	// PowerPC: 4 bytes.
	// Sparc:   4 bytes.
	// SystemZ: 2 bytes.
	// X86:     1 bytes.
	// XCore:   2 bytes.
	cs_skipdata_cb_t callback; 	// default value is NULL

	// User-defined data to be passed to @callback function pointer.
	void* user_data;
}

struct cs_detail {
	ubyte[12] regs_read; // list of implicit registers read by this insn
	ubyte regs_read_count; // number of implicit registers read by this insn

	ubyte[20] regs_write; // list of implicit registers modified by this insn
	ubyte regs_write_count; // number of implicit registers modified by this insn

	ubyte[8] groups; // list of group this instruction belong to
	ubyte groups_count; // number of groups this insn belongs to

	// Architecture-specific instruction info
	union {
		cs_x86 x86;	// X86 architecture, including 16-bit, 32-bit & 64-bit mode

		cs_arm64 arm64;	// ARM64 architecture (aka AArch64)
		cs_arm arm;		// ARM architecture (including Thumb/Thumb2)
		/*
		cs_mips mips;	// MIPS architecture
		cs_ppc ppc;	// PowerPC architecture
		cs_sparc sparc;	// Sparc architecture
		cs_sysz sysz;	// SystemZ architecture
		cs_xcore xcore;	// XCore architecture
        */
	};
}

struct cs_insn {
	// Instruction ID (basically a numeric ID for the instruction mnemonic)
	// Find the instruction id in the '[ARCH]_insn' enum in the header file 
	// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
	// 'x86_insn' in x86.h for X86, etc...
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
	uint id;

	// Address (EIP) of this instruction
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	ulong address;

	// Size of this instruction
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	ushort size;
	// Machine bytes of this instruction, with number of bytes indicated by @size above
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	ubyte[16] bytes;

	// Ascii text of instruction mnemonic
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	char[32] mnemonic;

	// Ascii text of instruction operands
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	char[160] op_str;

	// Pointer to cs_detail.
	// NOTE: detail pointer is only valid when both requirements below are met:
	// (1) CS_OP_DETAIL = CS_OPT_ON
	// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
	//
	// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
	//     is not NULL, its content is still irrelevant.
	cs_detail* detail;
}

extern (C){
    uint cs_version(int* major, int* minor);
    bool cs_support(int query);
    
    int cs_open(int arch, uint mode, size_t* handle);
    int cs_close(size_t* handle);
    
    int cs_option(size_t handle, int type, size_t value);
    
    int cs_errno(size_t handle);
    const(char)* cs_strerror(int code);
    
    size_t cs_disasm(size_t handle, const(ubyte)* code, size_t code_size, ulong address, size_t count, cs_insn** insn);

    
    void cs_free(cs_insn* insn, size_t count);
    cs_insn* cs_malloc(size_t handle);
    
    bool cs_disasm_iter(size_t handle, const(ubyte)** code, size_t* size, ulong* address, cs_insn* insn);

    const(char)* cs_reg_name(size_t handle, uint reg_id);
    const(char)* cs_insn_name(size_t handle, uint insn_id);
    const(char)* cs_group_name(size_t handle, uint group_id);
    // bool cs_insn_group(csh handle, const cs_insn *insn, unsigned int group_id);
    // bool cs_reg_read(csh handle, const cs_insn *insn, unsigned int reg_id);
    // bool cs_reg_write(csh handle, const cs_insn *insn, unsigned int reg_id);
}