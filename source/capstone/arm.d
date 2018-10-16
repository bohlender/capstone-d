module capstone.arm;

import capstone.internal.arm;
import capstone.utils;

import std.variant;
import std.exception: enforce;

// Instruction's operand referring to memory
// This is associated with ARM_OP_MEM operand type above
struct ArmOpMem {
	ArmRegister base;	// base register
	ArmRegister index;	// index register
	int scale;	// scale for index register (can be 1, or -1)
	int disp;	// displacement/offset value
}

struct ArmShift{
	ArmShiftType type;
	uint value;
}

alias ArmOpValue = TaggedUnion!(ArmRegister, "reg", int, "imm", double, "fp", ArmOpMem, "mem", ArmSetendType, "setend");

// Instruction operand
struct ArmOp {
	int vectorIndex;	// Vector Index for some vector operands (or -1 if irrelevant)
	ArmShift shift;
	ArmOpType type;	// operand type
	// TODO: hide?
	ArmOpValue value;
	alias value this; // for conventient access to value (as in original bindings)

	// in some instructions, an operand can be subtracted or added to
	// the base register,
	bool subtracted; // if TRUE, this operand is subtracted. otherwise, it is added.

	this(cs_arm_op internal){
		vectorIndex = internal.vector_index;
		shift = internal.shift;
		type = internal.type;
		final switch(internal.type){
			case ArmOpType.INVALID:
				break;
			case ArmOpType.REG, ArmOpType.SYSREG:
				value.reg = internal.reg;
				break;
			case ArmOpType.IMM, ArmOpType.CIMM, ArmOpType.PIMM:
				value.imm = internal.imm;
				break;
			case ArmOpType.MEM:
				value.mem = internal.mem;
				break;
			case ArmOpType.FP:
				value.fp = internal.fp;
				break;
			case ArmOpType.SETEND:
				value.setend = internal.setend;
				break;
		}
		subtracted = internal.subtracted;
	}
}

struct ArmInstructionDetail {
	bool usermode;	// User-mode registers to be loaded (for LDM/STM instructions)
	int vectorSize; 	// Scalar size for vector instructions
	ArmVectordataType vectorData; // Data type for elements of vector instructions
	ArmCpsmodeType cpsMode;	// CPS mode for CPS instruction
	ArmCpsflagType cpsFlag;	// CPS mode for CPS instruction
	ArmCc cc;			// conditional code for this insn
	bool updateFlags;	// does this insn update flags?
	bool writeback;		// does this insn write-back?
	ArmMemBarrier memBarrier;	// Option for some memory barrier instructions

	ArmOp[] operands;	// operands for this instruction.

	this(cs_arm internal){
		usermode = internal.usermode;
		vectorSize = internal.vector_size;
		vectorData = internal.vector_data;
		cpsMode = internal.cps_mode;
		cpsFlag = internal.cps_flag;
		cc = internal.cc;
		updateFlags = internal.update_flags;
		writeback = internal.writeback;
		memBarrier = internal.mem_barrier;

		foreach(op; internal.operands[0..internal.op_count])
			operands ~= ArmOp(op);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Constants
///////////////////////////////////////////////////////////////////////////////

//> ARM shift type
enum ArmShiftType {
	INVALID = 0,
	ASR,	// shift with immediate const
	LSL,	// shift with immediate const
	LSR,	// shift with immediate const
	ROR,	// shift with immediate const
	RRX,	// shift with immediate const
	ASR_REG,	// shift with register
	LSL_REG,	// shift with register
	LSR_REG,	// shift with register
	ROR_REG,	// shift with register
	RRX_REG,	// shift with register
}

//> ARM condition code
enum ArmCc {
	INVALID = 0,
	EQ,            // Equal                      Equal
	NE,            // Not equal                  Not equal, or unordered
	HS,            // Carry set                  >, ==, or unordered
	LO,            // Carry clear                Less than
	MI,            // Minus, negative            Less than
	PL,            // Plus, positive or zero     >, ==, or unordered
	VS,            // Overflow                   Unordered
	VC,            // No overflow                Not unordered
	HI,            // Unsigned higher            Greater than, or unordered
	LS,            // Unsigned lower or same     Less than or equal
	GE,            // Greater than or equal      Greater than or equal
	LT,            // Less than                  Less than, or unordered
	GT,            // Greater than               Greater than
	LE,            // Less than or equal         <, ==, or unordered
	AL             // Always (unconditional)     Always (unconditional)
}

enum ArmSysreg {
	//> Special registers for MSR
	INVALID = 0,

	// SPSR* registers can be OR combined
	SPSR_C = 1,
	SPSR_X = 2,
	SPSR_S = 4,
	SPSR_F = 8,

	// CPSR* registers can be OR combined
	CPSR_C = 16,
	CPSR_X = 32,
	CPSR_S = 64,
	CPSR_F = 128,

	// independent registers
	APSR = 256,
	APSR_G,
	APSR_NZCVQ,
	APSR_NZCVQG,

	IAPSR,
	IAPSR_G,
	IAPSR_NZCVQG,

	EAPSR,
	EAPSR_G,
	EAPSR_NZCVQG,

	XPSR,
	XPSR_G,
	XPSR_NZCVQG,

	IPSR,
	EPSR,
	IEPSR,

	MSP,
	PSP,
	PRIMASK,
	BASEPRI,
	BASEPRI_MAX,
	FAULTMASK,
	CONTROL,
}

//> The memory barrier constants map directly to the 4-bit encoding of
//> the option field for Memory Barrier operations.
enum ArmMemBarrier {
	INVALID = 0,
	RESERVED_0,
	OSHLD,
	OSHST,
	OSH,
	RESERVED_4,
	NSHLD,
	NSHST,
	NSH,
	RESERVED_8,
	ISHLD,
	ISHST,
	ISH,
	RESERVED_12,
	LD,
	ST,
	SY,
}

//> Operand type for instruction's operands
enum ArmOpType {
	INVALID = 0, // = CS_OP_INVALID (Uninitialized).
	REG, // = CS_OP_REG (Register operand).
	IMM, // = CS_OP_IMM (Immediate operand).
	MEM, // = CS_OP_MEM (Memory operand).
	FP,  // = CS_OP_FP (Floating-Point operand).
	CIMM = 64, // C-Immediate (coprocessor registers)
	PIMM, // P-Immediate (coprocessor registers)
	SETEND,	// operand for SETEND instruction
	SYSREG,	// MSR/MRS special register operand
}

//> Operand type for SETEND instruction
enum ArmSetendType {
	INVALID = 0,	// Uninitialized.
	BE,	// BE operand.
	LE, // LE operand
}

enum ArmCpsmodeType {
	INVALID = 0,
	IE = 2,
	ID = 3
}

//> Operand type for SETEND instruction
enum ArmCpsflagType {
	INVALID = 0,
	F = 1,
	I = 2,
	A = 4,
	NONE = 16,	// no flag
}

//> Data type for elements of vector instructions.
enum ArmVectordataType {
	INVALID = 0,

	// Integer type
	I8,
	I16,
	I32,
	I64,

	// Signed integer type
	S8,
	S16,
	S32,
	S64,

	// Unsigned integer type
	U8,
	U16,
	U32,
	U64,

	// Data type for VMUL/VMULL
	P8,

	// Floating type
	F32,
	F64,

	// Convert float <-> float
	F16F64,	// f16.f64
	F64F16,	// f64.f16
	F32F16,	// f32.f16
	F16F32,	// f32.f16
	F64F32,	// f64.f32
	F32F64,	// f32.f64

	// Convert integer <-> float
	S32F32,	// s32.f32
	U32F32,	// u32.f32
	F32S32,	// f32.s32
	F32U32,	// f32.u32
	F64S16,	// f64.s16
	F32S16,	// f32.s16
	F64S32,	// f64.s32
	S16F64,	// s16.f64
	S16F32,	// s16.f64
	S32F64,	// s32.f64
	U16F64,	// u16.f64
	U16F32,	// u16.f32
	U32F64,	// u32.f64
	F64U16,	// f64.u16
	F32U16,	// f32.u16
	F64U32,	// f64.u32
}

//> ARM registers
enum ArmRegister {
	INVALID = 0,
	APSR,
	APSR_NZCV,
	CPSR,
	FPEXC,
	FPINST,
	FPSCR,
	FPSCR_NZCV,
	FPSID,
	ITSTATE,
	LR,
	PC,
	SP,
	SPSR,
	D0,
	D1,
	D2,
	D3,
	D4,
	D5,
	D6,
	D7,
	D8,
	D9,
	D10,
	D11,
	D12,
	D13,
	D14,
	D15,
	D16,
	D17,
	D18,
	D19,
	D20,
	D21,
	D22,
	D23,
	D24,
	D25,
	D26,
	D27,
	D28,
	D29,
	D30,
	D31,
	FPINST2,
	MVFR0,
	MVFR1,
	MVFR2,
	Q0,
	Q1,
	Q2,
	Q3,
	Q4,
	Q5,
	Q6,
	Q7,
	Q8,
	Q9,
	Q10,
	Q11,
	Q12,
	Q13,
	Q14,
	Q15,
	R0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	R8,
	R9,
	R10,
	R11,
	R12,
	S0,
	S1,
	S2,
	S3,
	S4,
	S5,
	S6,
	S7,
	S8,
	S9,
	S10,
	S11,
	S12,
	S13,
	S14,
	S15,
	S16,
	S17,
	S18,
	S19,
	S20,
	S21,
	S22,
	S23,
	S24,
	S25,
	S26,
	S27,
	S28,
	S29,
	S30,
	S31,

	//> alias registers
	R13 = SP,
	R14 = LR,
	R15 = PC,

	SB = R9,
	SL = R10,
	FP = R11,
	IP = R12,
}

//> ARM instruction
enum ArmInstructionId {
	INVALID = 0,

	ADC,
	ADD,
	ADR,
	AESD,
	AESE,
	AESIMC,
	AESMC,
	AND,
	BFC,
	BFI,
	BIC,
	BKPT,
	BL,
	BLX,
	BX,
	BXJ,
	B,
	CDP,
	CDP2,
	CLREX,
	CLZ,
	CMN,
	CMP,
	CPS,
	CRC32B,
	CRC32CB,
	CRC32CH,
	CRC32CW,
	CRC32H,
	CRC32W,
	DBG,
	DMB,
	DSB,
	EOR,
	VMOV,
	FLDMDBX,
	FLDMIAX,
	VMRS,
	FSTMDBX,
	FSTMIAX,
	HINT,
	HLT,
	ISB,
	LDA,
	LDAB,
	LDAEX,
	LDAEXB,
	LDAEXD,
	LDAEXH,
	LDAH,
	LDC2L,
	LDC2,
	LDCL,
	LDC,
	LDMDA,
	LDMDB,
	LDM,
	LDMIB,
	LDRBT,
	LDRB,
	LDRD,
	LDREX,
	LDREXB,
	LDREXD,
	LDREXH,
	LDRH,
	LDRHT,
	LDRSB,
	LDRSBT,
	LDRSH,
	LDRSHT,
	LDRT,
	LDR,
	MCR,
	MCR2,
	MCRR,
	MCRR2,
	MLA,
	MLS,
	MOV,
	MOVT,
	MOVW,
	MRC,
	MRC2,
	MRRC,
	MRRC2,
	MRS,
	MSR,
	MUL,
	MVN,
	ORR,
	PKHBT,
	PKHTB,
	PLDW,
	PLD,
	PLI,
	QADD,
	QADD16,
	QADD8,
	QASX,
	QDADD,
	QDSUB,
	QSAX,
	QSUB,
	QSUB16,
	QSUB8,
	RBIT,
	REV,
	REV16,
	REVSH,
	RFEDA,
	RFEDB,
	RFEIA,
	RFEIB,
	RSB,
	RSC,
	SADD16,
	SADD8,
	SASX,
	SBC,
	SBFX,
	SDIV,
	SEL,
	SETEND,
	SHA1C,
	SHA1H,
	SHA1M,
	SHA1P,
	SHA1SU0,
	SHA1SU1,
	SHA256H,
	SHA256H2,
	SHA256SU0,
	SHA256SU1,
	SHADD16,
	SHADD8,
	SHASX,
	SHSAX,
	SHSUB16,
	SHSUB8,
	SMC,
	SMLABB,
	SMLABT,
	SMLAD,
	SMLADX,
	SMLAL,
	SMLALBB,
	SMLALBT,
	SMLALD,
	SMLALDX,
	SMLALTB,
	SMLALTT,
	SMLATB,
	SMLATT,
	SMLAWB,
	SMLAWT,
	SMLSD,
	SMLSDX,
	SMLSLD,
	SMLSLDX,
	SMMLA,
	SMMLAR,
	SMMLS,
	SMMLSR,
	SMMUL,
	SMMULR,
	SMUAD,
	SMUADX,
	SMULBB,
	SMULBT,
	SMULL,
	SMULTB,
	SMULTT,
	SMULWB,
	SMULWT,
	SMUSD,
	SMUSDX,
	SRSDA,
	SRSDB,
	SRSIA,
	SRSIB,
	SSAT,
	SSAT16,
	SSAX,
	SSUB16,
	SSUB8,
	STC2L,
	STC2,
	STCL,
	STC,
	STL,
	STLB,
	STLEX,
	STLEXB,
	STLEXD,
	STLEXH,
	STLH,
	STMDA,
	STMDB,
	STM,
	STMIB,
	STRBT,
	STRB,
	STRD,
	STREX,
	STREXB,
	STREXD,
	STREXH,
	STRH,
	STRHT,
	STRT,
	STR,
	SUB,
	SVC,
	SWP,
	SWPB,
	SXTAB,
	SXTAB16,
	SXTAH,
	SXTB,
	SXTB16,
	SXTH,
	TEQ,
	TRAP,
	TST,
	UADD16,
	UADD8,
	UASX,
	UBFX,
	UDF,
	UDIV,
	UHADD16,
	UHADD8,
	UHASX,
	UHSAX,
	UHSUB16,
	UHSUB8,
	UMAAL,
	UMLAL,
	UMULL,
	UQADD16,
	UQADD8,
	UQASX,
	UQSAX,
	UQSUB16,
	UQSUB8,
	USAD8,
	USADA8,
	USAT,
	USAT16,
	USAX,
	USUB16,
	USUB8,
	UXTAB,
	UXTAB16,
	UXTAH,
	UXTB,
	UXTB16,
	UXTH,
	VABAL,
	VABA,
	VABDL,
	VABD,
	VABS,
	VACGE,
	VACGT,
	VADD,
	VADDHN,
	VADDL,
	VADDW,
	VAND,
	VBIC,
	VBIF,
	VBIT,
	VBSL,
	VCEQ,
	VCGE,
	VCGT,
	VCLE,
	VCLS,
	VCLT,
	VCLZ,
	VCMP,
	VCMPE,
	VCNT,
	VCVTA,
	VCVTB,
	VCVT,
	VCVTM,
	VCVTN,
	VCVTP,
	VCVTT,
	VDIV,
	VDUP,
	VEOR,
	VEXT,
	VFMA,
	VFMS,
	VFNMA,
	VFNMS,
	VHADD,
	VHSUB,
	VLD1,
	VLD2,
	VLD3,
	VLD4,
	VLDMDB,
	VLDMIA,
	VLDR,
	VMAXNM,
	VMAX,
	VMINNM,
	VMIN,
	VMLA,
	VMLAL,
	VMLS,
	VMLSL,
	VMOVL,
	VMOVN,
	VMSR,
	VMUL,
	VMULL,
	VMVN,
	VNEG,
	VNMLA,
	VNMLS,
	VNMUL,
	VORN,
	VORR,
	VPADAL,
	VPADDL,
	VPADD,
	VPMAX,
	VPMIN,
	VQABS,
	VQADD,
	VQDMLAL,
	VQDMLSL,
	VQDMULH,
	VQDMULL,
	VQMOVUN,
	VQMOVN,
	VQNEG,
	VQRDMULH,
	VQRSHL,
	VQRSHRN,
	VQRSHRUN,
	VQSHL,
	VQSHLU,
	VQSHRN,
	VQSHRUN,
	VQSUB,
	VRADDHN,
	VRECPE,
	VRECPS,
	VREV16,
	VREV32,
	VREV64,
	VRHADD,
	VRINTA,
	VRINTM,
	VRINTN,
	VRINTP,
	VRINTR,
	VRINTX,
	VRINTZ,
	VRSHL,
	VRSHRN,
	VRSHR,
	VRSQRTE,
	VRSQRTS,
	VRSRA,
	VRSUBHN,
	VSELEQ,
	VSELGE,
	VSELGT,
	VSELVS,
	VSHLL,
	VSHL,
	VSHRN,
	VSHR,
	VSLI,
	VSQRT,
	VSRA,
	VSRI,
	VST1,
	VST2,
	VST3,
	VST4,
	VSTMDB,
	VSTMIA,
	VSTR,
	VSUB,
	VSUBHN,
	VSUBL,
	VSUBW,
	VSWP,
	VTBL,
	VTBX,
	VCVTR,
	VTRN,
	VTST,
	VUZP,
	VZIP,
	ADDW,
	ASR,
	DCPS1,
	DCPS2,
	DCPS3,
	IT,
	LSL,
	LSR,
	ASRS,
	LSRS,
	ORN,
	ROR,
	RRX,
	SUBS,
	SUBW,
	TBB,
	TBH,
	CBNZ,
	CBZ,
	MOVS,
	POP,
	PUSH,

	// special instructions
	NOP,
	YIELD,
	WFE,
	WFI,
	SEV,
	SEVL,
	VPUSH,
	VPOP
}

//> Group of ARM instructions
enum ArmInstructionGroup {
	INVALID = 0, // = CS_GRP_INVALID

	//> Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	JUMP,	// = CS_GRP_JUMP

	//> Architecture-specific groups
	CRYPTO = 128,
	DATABARRIER,
	DIVIDE,
	FPARMV8,
	MULTPRO,
	NEON,
	T2EXTRACTPACK,
	THUMB2DSP,
	TRUSTZONE,
	V4T,
	V5T,
	V5TE,
	V6,
	V6T2,
	V7,
	V8,
	VFP2,
	VFP3,
	VFP4,
	ARM,
	MCLASS,
	NOTMCLASS,
	THUMB,
	THUMB1ONLY,
	THUMB2,
	PREV8,
	FPVMLX,
	MULOPS,
	CRC,
	DPVFP,
	V6M
}