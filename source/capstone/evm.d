/// Types and constants of EVM architecture
module capstone.evm;

import std.conv: to;

import capstone.api;
import capstone.capstone;
import capstone.detail;
import capstone.instruction;
import capstone.instructiongroup;
import capstone.internal;
import capstone.register;
import capstone.utils;

/** Architecture-specific Register variant

Note that this is a dummy enum as there are no valid registers
*/
class EvmRegister : RegisterImpl!EvmRegisterId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class EvmInstructionGroup : InstructionGroupImpl!EvmInstructionGroupId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class EvmDetail : DetailImpl!(EvmRegister, EvmInstructionGroup, EvmInstructionDetail) {
    package this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class EvmInstruction : InstructionImpl!(EvmInstructionId, EvmRegister, EvmDetail) {
    package this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneEvm : CapstoneImpl!(EvmInstructionId, EvmInstruction) {
    /** Creates an architecture-specific instance with a given mode of interpretation
    
    Params:
        modeFlags = The (initial) mode of interpretation, which can still be changed later on
    */
	this(in ModeFlags modeFlags){
        super(Arch.evm, modeFlags);
    }
}

/// Evm-specific information about an instruction
struct EvmInstructionDetail {
    ubyte pop;  /// Number of items popped from the stack
    ubyte push; /// Number of items pushed into the stack
    uint fee;   /// Gas fee for the instruction

    package this(in Capstone cs, cs_arch_detail arch_detail){
        const internal = arch_detail.evm;
		pop = internal.pop;
		push = internal.push;
		fee = internal.fee;
    }
}

//=============================================================================
// Constants
//=============================================================================

/** EVM register

Note that this is a dummy enum as there are no valid registers
*/
enum EvmRegisterId {
	invalid = 0
}

/// EVM instruction
enum EvmInstructionId {
	stop = 0,
	add = 1,
	mul = 2,
	sub = 3,
	div = 4,
	sdiv = 5,
	mod = 6,
	smod = 7,
	addmod = 8,
	mulmod = 9,
	exp = 10,
	signextend = 11,
	lt = 16,
	gt = 17,
	slt = 18,
	sgt = 19,
	eq = 20,
	iszero = 21,
	and = 22,
	or = 23,
	xor = 24,
	not = 25,
	byte_ = 26,
	sha3 = 32,
	address = 48,
	balance = 49,
	origin = 50,
	caller = 51,
	callvalue = 52,
	calldataload = 53,
	calldatasize = 54,
	calldatacopy = 55,
	codesize = 56,
	codecopy = 57,
	gasprice = 58,
	extcodesize = 59,
	extcodecopy = 60,
	returndatasize = 61,
	returndatacopy = 62,
	blockhash = 64,
	coinbase = 65,
	timestamp = 66,
	number = 67,
	difficulty = 68,
	gaslimit = 69,
	pop = 80,
	mload = 81,
	mstore = 82,
	mstore8 = 83,
	sload = 84,
	sstore = 85,
	jump = 86,
	jumpi = 87,
	pc = 88,
	msize = 89,
	gas = 90,
	jumpdest = 91,
	push1 = 96,
	push2 = 97,
	push3 = 98,
	push4 = 99,
	push5 = 100,
	push6 = 101,
	push7 = 102,
	push8 = 103,
	push9 = 104,
	push10 = 105,
	push11 = 106,
	push12 = 107,
	push13 = 108,
	push14 = 109,
	push15 = 110,
	push16 = 111,
	push17 = 112,
	push18 = 113,
	push19 = 114,
	push20 = 115,
	push21 = 116,
	push22 = 117,
	push23 = 118,
	push24 = 119,
	push25 = 120,
	push26 = 121,
	push27 = 122,
	push28 = 123,
	push29 = 124,
	push30 = 125,
	push31 = 126,
	push32 = 127,
	dup1 = 128,
	dup2 = 129,
	dup3 = 130,
	dup4 = 131,
	dup5 = 132,
	dup6 = 133,
	dup7 = 134,
	dup8 = 135,
	dup9 = 136,
	dup10 = 137,
	dup11 = 138,
	dup12 = 139,
	dup13 = 140,
	dup14 = 141,
	dup15 = 142,
	dup16 = 143,
	swap1 = 144,
	swap2 = 145,
	swap3 = 146,
	swap4 = 147,
	swap5 = 148,
	swap6 = 149,
	swap7 = 150,
	swap8 = 151,
	swap9 = 152,
	swap10 = 153,
	swap11 = 154,
	swap12 = 155,
	swap13 = 156,
	swap14 = 157,
	swap15 = 158,
	swap16 = 159,
	log0 = 160,
	log1 = 161,
	log2 = 162,
	log3 = 163,
	log4 = 164,
	create = 240,
	call = 241,
	callcode = 242,
	return_ = 243,
	delegatecall = 244,
	callblackbox = 245,
	staticcall = 250,
	revert = 253,
	suicide = 255,

	invalid = 512
}

/// Group of EVM instructions
enum EvmInstructionGroupId {
	invalid = 0,   // cs_grp_invalid

	jump,          // all jump instructions

	math = 8,      // math instructions
	stack_write,   // instructions write to stack
	stack_read,    // instructions read from stack
	mem_write,     // instructions write to memory
	mem_read,      // instructions read from memory
	store_write,   // instructions write to storage
	store_read,    // instructions read from storage
	halt   		   // instructions halt execution
}