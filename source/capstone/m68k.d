/// Types and constants of M68k architecture
module capstone.m68k;

import std.conv: to;

import capstone.api;
import capstone.capstone;
import capstone.detail;
import capstone.instruction;
import capstone.instructiongroup;
import capstone.internal;
import capstone.register;
import capstone.utils;

/// Architecture-specific Register variant
class M68kRegister : RegisterImpl!M68kRegisterId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class M68kInstructionGroup : InstructionGroupImpl!M68kInstructionGroupId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class M68kDetail : DetailImpl!(M68kRegister, M68kInstructionGroup, M68kInstructionDetail) {
    package this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class M68kInstruction : InstructionImpl!(M68kInstructionId, M68kRegister, M68kDetail) {
    package this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneM68k : CapstoneImpl!(M68kInstructionId, M68kInstruction) {
    /** Creates an architecture-specific instance with a given mode of interpretation
    
    Params:
        modeFlags = The (initial) mode of interpretation, which can still be changed later on
    */
	this(in ModeFlags modeFlags){
        super(Arch.m68k, modeFlags);
    }
}

/** Instruction's operand referring to memory

This is associated with the `M68kOpType.mem` operand type
*/
struct M68kOpMem {
    M68kRegister baseReg;   /// Base register (or M68K_REG_INVALID if irrelevant)
    M68kRegister indexReg;  /// Index register (or M68K_REG_INVALID if irrelevant)
    M68kRegister inBaseReg; /// Indirect base register (or M68K_REG_INVALID if irrelevant)
    uint inDisp;            /// Indirect displacement
    uint outDisp;           /// Other displacement
    short disp;	            /// Displacement value
    ubyte scale;            /// Scale for index register
    ubyte bitfield;         /// Set to true if the two values below should be used
    ubyte width;            /// Used for bf* instructions
    ubyte offset;           /// Used for bf* instructions
    ubyte indexSize;        /// 0 = w, 1 = l

	package this(in Capstone cs, m68k_op_mem internal) {
		baseReg = new M68kRegister(cs, internal.base_reg);
		indexReg = new M68kRegister(cs, internal.index_reg);
		inBaseReg = new M68kRegister(cs, internal.in_base_reg);
		inDisp = internal.in_disp;
		outDisp = internal.out_disp;
		disp = internal.disp;
		scale = internal.scale;
		bitfield = internal.bitfield;
		width = internal.width;
		offset = internal.offset;
		indexSize = internal.index_size;
	}
}

/// Branch displacement operand data
struct M68kOpBrDisp {
	int disp;       /// Displacement value
	ubyte dispSize; /// Size from m68k_op_br_disp_size type above

	package this(m68k_op_br_disp internal) {
		disp = internal.disp;
		dispSize = internal.disp_size;
	}
}

/// Union of possible operand types
union M68kOpValue{
	ulong imm;               /// Immediate value for IMM operand
	double dimm;             /// Double imm
	float simm;              /// Float imm
	M68kRegister reg;        /// Register value for REG operand
	M68kRegister[2] regPair; /// Register pair in one operand
	M68kOpMem mem; 	         /// Data when operand is targeting memory
	M68kOpBrDisp brDisp;     /// Data when operand is a branch displacement
	uint registerBits;       /// Register bits for movem etc. (always in d0-d7, a0-a7, fp0 - fp7 order)
}

/// Instruction's operand
struct M68kOp {
	M68kOpType type;             /// Operand type
    SafeUnion!M68kOpValue value; /// Operand value of type `type`
    alias value this;            /// Convenient access to value (as in original bindings)

	M68kAddressMode addressMode; /// M68k addressing mode for this op

    package this(in Capstone cs, cs_m68k_op internal) {
        type = internal.type.to!M68kOpType;
        final switch(type) {
			case M68kOpType.invalid:
				break;
			case M68kOpType.reg:
				value.reg = new M68kRegister(cs, internal.reg);
				break;
			case M68kOpType.imm:
				value.imm = internal.imm;
				break;
			case M68kOpType.mem:
				value.mem = M68kOpMem(cs, internal.mem);
				break;
			case M68kOpType.fpSingle:
				value.simm = internal.simm;
				break;
			case M68kOpType.fpDouble:
				value.dimm = internal.dimm;
				break;
			case M68kOpType.regBits:
				value.registerBits = internal.register_bits;
				break;
			case M68kOpType.regPair:
				value.regPair = [new M68kRegister(cs, internal.reg_pair.reg_0), new M68kRegister(cs, internal.reg_pair.reg_1)];
				break;
			case M68kOpType.brDisp:
				value.brDisp = M68kOpBrDisp(internal.br_disp);
				break;
		}
		addressMode = internal.address_mode.to!M68kAddressMode;
	}
}

/// Operation size of the current instruction (NOT the actual size of instruction)
struct M68kOpSize {
	M68kSizeType type; /// Type of size
	union {
		M68kCpuSize cpuSize; /// Size of CPU instruction
		M68kFpuSize fpuSize; /// Size of the FPU instruction
	}
}

/// M68k-specific information about an instruction
struct M68kInstructionDetail {
	M68kOp[] operands; /// Operands for this instruction.
	M68kOpSize opSize; /// Size of data operand works on in bytes (.b, .w, .l, etc)

	package this(in Capstone cs, cs_arch_detail arch_detail){
        auto internal = arch_detail.m68k;
        foreach(op; internal.operands[0..internal.op_count])
            operands ~= M68kOp(cs, op);
    }
}

//=============================================================================
// Constants
//=============================================================================

/// M68k Addressing Modes
enum M68kAddressMode {
	none = 0,			    /// No address mode.

	reg_direct_data,		/// Register direct - data
	reg_direct_addr,		/// Register direct - address

	regi_addr,				/// Register indirect - address
	regi_addr_post_inc,		/// Register indirect - address with postincrement
	regi_addr_pre_dec,		/// Register indirect - address with predecrement
	regi_addr_disp,			/// Register indirect - address with displacement

	aregi_index_8_bit_disp,	/// Address register indirect with index- 8-bit displacement
	aregi_index_base_disp,	/// Address register indirect with index- base displacement

	memi_post_index,		/// Memory indirect - postindex
	memi_pre_index,			/// Memory indirect - preindex

	pci_disp,				/// Program counter indirect - with displacement

	pci_index_8_bit_disp,	/// Program counter indirect with index - with 8-bit displacement
	pci_index_base_disp,	/// Program counter indirect with index - with base displacement

	pc_memi_post_index,		/// Program counter memory indirect - postindexed
	pc_memi_pre_index,		/// Program counter memory indirect - preindexed

	absolute_data_short,	/// Absolute data addressing  - short
	absolute_data_long,		/// Absolute data addressing  - long
	immediate,              /// Immediate value

	branch_displacement     /// Address as displacement from (pc+2) used by branches
}

/// Operand type for instruction's operands
enum M68kOpType {
	invalid = 0, /// Uninitialized
	reg,         /// Register operand
	imm,         /// Immediate operand
	mem,         /// Memory operand
	fpSingle,    /// Single precision Floating-Point operand
	fpDouble,    /// Double precision Floating-Point operand
	regBits,     /// Register bits move
	regPair,     /// Register pair in the same op (upper 4 bits for first reg, lower for second)
	brDisp       /// Branch displacement
}

/// Displacement size of branch displacement operand 
enum M68kOpBrDispSize {
	invalid = 0, /// Uninitialized
	byte_ = 1,   /// Signed 8-bit displacement
	word = 2,    /// Signed 16-bit displacement
	long_ = 4,   /// Signed 32-bit displacement
}

/// Operation size of the CPU instructions
enum M68kCpuSize {
	none = 0,	// unsized or unspecified
	byte_ = 1,	// 1 byte in size
	word = 2,	// 2 bytes in size
	long_ = 4,	// 4 bytes in size
}

/** Operation size of the FPU instructions

Notice that FPU instruction can also use CPU sizes if needed
*/
enum M68kFpuSize {
	none = 0,		/// Unsized like fsave/frestore
	single = 4,		/// 4 byte in size (single float)
	double_ = 8,	/// 8 byte in size (double)
	extended = 12,	/// 12 byte in size (extended real format)
}

/// Type of size that is being used for the current instruction
enum M68kSizeType {
	invalid = 0,

	cpu,
	fpu,
}

/// M68k registers and special registers
enum M68kRegisterId {
	invalid = 0,

	d0,
	d1,
	d2,
	d3,
	d4,
	d5,
	d6,
	d7,

	a0,
	a1,
	a2,
	a3,
	a4,
	a5,
	a6,
	a7,

	fp0,
	fp1,
	fp2,
	fp3,
	fp4,
	fp5,
	fp6,
	fp7,

	pc,

	sr,
	ccr,
	sfc,
	dfc,
	usp,
	vbr,
	cacr,
	caar,
	msp,
	isp,
	tc,
	itt0,
	itt1,
	dtt0,
	dtt1,
	mmusr,
	urp,
	srp,

	fpcr,
	fpsr,
	fpiar
}

/// M68k instruction
enum M68kInstructionId {
	invalid = 0,

	abcd,
	add,
	adda,
	addi,
	addq,
	addx,
	and,
	andi,
	asl,
	asr,
	bhs,
	blo,
	bhi,
	bls,
	bcc,
	bcs,
	bne,
	beq,
	bvc,
	bvs,
	bpl,
	bmi,
	bge,
	blt,
	bgt,
	ble,
	bra,
	bsr,
	bchg,
	bclr,
	bset,
	btst,
	bfchg,
	bfclr,
	bfexts,
	bfextu,
	bfffo,
	bfins,
	bfset,
	bftst,
	bkpt,
	callm,
	cas,
	cas2,
	chk,
	chk2,
	clr,
	cmp,
	cmpa,
	cmpi,
	cmpm,
	cmp2,
	cinvl,
	cinvp,
	cinva,
	cpushl,
	cpushp,
	cpusha,
	dbt,
	dbf,
	dbhi,
	dbls,
	dbcc,
	dbcs,
	dbne,
	dbeq,
	dbvc,
	dbvs,
	dbpl,
	dbmi,
	dbge,
	dblt,
	dbgt,
	dble,
	dbra,
	divs,
	divsl,
	divu,
	divul,
	eor,
	eori,
	exg,
	ext,
	extb,
	fabs,
	fsabs,
	fdabs,
	facos,
	fadd,
	fsadd,
	fdadd,
	fasin,
	fatan,
	fatanh,
	fbf,
	fbeq,
	fbogt,
	fboge,
	fbolt,
	fbole,
	fbogl,
	fbor,
	fbun,
	fbueq,
	fbugt,
	fbuge,
	fbult,
	fbule,
	fbne,
	fbt,
	fbsf,
	fbseq,
	fbgt,
	fbge,
	fblt,
	fble,
	fbgl,
	fbgle,
	fbngle,
	fbngl,
	fbnle,
	fbnlt,
	fbnge,
	fbngt,
	fbsne,
	fbst,
	fcmp,
	fcos,
	fcosh,
	fdbf,
	fdbeq,
	fdbogt,
	fdboge,
	fdbolt,
	fdbole,
	fdbogl,
	fdbor,
	fdbun,
	fdbueq,
	fdbugt,
	fdbuge,
	fdbult,
	fdbule,
	fdbne,
	fdbt,
	fdbsf,
	fdbseq,
	fdbgt,
	fdbge,
	fdblt,
	fdble,
	fdbgl,
	fdbgle,
	fdbngle,
	fdbngl,
	fdbnle,
	fdbnlt,
	fdbnge,
	fdbngt,
	fdbsne,
	fdbst,
	fdiv,
	fsdiv,
	fddiv,
	fetox,
	fetoxm1,
	fgetexp,
	fgetman,
	fint,
	fintrz,
	flog10,
	flog2,
	flogn,
	flognp1,
	fmod,
	fmove,
	fsmove,
	fdmove,
	fmovecr,
	fmovem,
	fmul,
	fsmul,
	fdmul,
	fneg,
	fsneg,
	fdneg,
	fnop,
	frem,
	frestore,
	fsave,
	fscale,
	fsgldiv,
	fsglmul,
	fsin,
	fsincos,
	fsinh,
	fsqrt,
	fssqrt,
	fdsqrt,
	fsf,
	fsbeq,
	fsogt,
	fsoge,
	fsolt,
	fsole,
	fsogl,
	fsor,
	fsun,
	fsueq,
	fsugt,
	fsuge,
	fsult,
	fsule,
	fsne,
	fst,
	fssf,
	fsseq,
	fsgt,
	fsge,
	fslt,
	fsle,
	fsgl,
	fsgle,
	fsngle,
	fsngl,
	fsnle,
	fsnlt,
	fsnge,
	fsngt,
	fssne,
	fsst,
	fsub,
	fssub,
	fdsub,
	ftan,
	ftanh,
	ftentox,
	ftrapf,
	ftrapeq,
	ftrapogt,
	ftrapoge,
	ftrapolt,
	ftrapole,
	ftrapogl,
	ftrapor,
	ftrapun,
	ftrapueq,
	ftrapugt,
	ftrapuge,
	ftrapult,
	ftrapule,
	ftrapne,
	ftrapt,
	ftrapsf,
	ftrapseq,
	ftrapgt,
	ftrapge,
	ftraplt,
	ftraple,
	ftrapgl,
	ftrapgle,
	ftrapngle,
	ftrapngl,
	ftrapnle,
	ftrapnlt,
	ftrapnge,
	ftrapngt,
	ftrapsne,
	ftrapst,
	ftst,
	ftwotox,
	halt,
	illegal,
	jmp,
	jsr,
	lea,
	link,
	lpstop,
	lsl,
	lsr,
	move,
	movea,
	movec,
	movem,
	movep,
	moveq,
	moves,
	move16,
	muls,
	mulu,
	nbcd,
	neg,
	negx,
	nop,
	not,
	or,
	ori,
	pack,
	pea,
	pflush,
	pflusha,
	pflushan,
	pflushn,
	ploadr,
	ploadw,
	plpar,
	plpaw,
	pmove,
	pmovefd,
	ptestr,
	ptestw,
	pulse,
	rems,
	remu,
	reset,
	rol,
	ror,
	roxl,
	roxr,
	rtd,
	rte,
	rtm,
	rtr,
	rts,
	sbcd,
	st,
	sf,
	shi,
	sls,
	scc,
	shs,
	scs,
	slo,
	sne,
	seq,
	svc,
	svs,
	spl,
	smi,
	sge,
	slt,
	sgt,
	sle,
	stop,
	sub,
	suba,
	subi,
	subq,
	subx,
	swap,
	tas,
	trap,
	trapv,
	trapt,
	trapf,
	traphi,
	trapls,
	trapcc,
	traphs,
	trapcs,
	traplo,
	trapne,
	trapeq,
	trapvc,
	trapvs,
	trappl,
	trapmi,
	trapge,
	traplt,
	trapgt,
	traple,
	tst,
	unlk,
	unpk,
}

/// Group of M68k instructions
enum M68kInstructionGroupId {
	invalid = 0,
	jump,
	ret = 3,
	iret = 5,
	branch_relative = 7
}