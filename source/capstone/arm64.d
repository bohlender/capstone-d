module capstone.arm64;

import capstone.internal.arm64;
import capstone.utils;

import std.variant;
import std.exception: enforce;

// Instruction's operand referring to memory
// This is associated with MEM operand type above
struct Arm64OpMem {
	Arm64Register base;	// base register
	Arm64Register index;	// index register
	int disp;	// displacement/offset value
}

struct Arm64Shift{
	Arm64ShiftType type;	// shifter type of this operand
	uint value;	// shifter value of this operand
}

alias Arm64OperandValue = TaggedUnion!(Arm64Register, "reg", long, "imm", double, "fp", Arm64OpMem, "mem", Arm64PState, "pstate", uint, "sys", Arm64PrefetchOp, "prefetch", Arm64BarrierOp, "barrier");

// Instruction operand
struct Arm64Op {
	int vectorIndex;	// Vector Index for some vector operands (or -1 if irrelevant)
	Arm64Vas vas;		// Vector Arrangement Specifier
	Arm64Vess vess;	// Vector Element Size Specifier
	Arm64Shift shift;
	Arm64Extender ext;		// extender type of this operand
	Arm64OpType type;	// operand type
	Arm64OperandValue value;
	alias value this; // for conventient access to value (as in original bindings)

	this(cs_arm64_op internal){
		vectorIndex = internal.vector_index;
		vas = internal.vas;
		vess = internal.vess;
		shift = internal.shift;
		ext = internal.ext;
		type = internal.type;
		
		final switch(internal.type){
			case Arm64OpType.invalid:
				break;
			case Arm64OpType.reg, Arm64OpType.reg_mrs, Arm64OpType.reg_msr:
				value.reg = internal.reg;
				break;
			case Arm64OpType.imm, Arm64OpType.cimm:
				value.imm = internal.imm;
				break;
			case Arm64OpType.mem:
				value.mem = internal.mem;
				break;
			case Arm64OpType.fp:
				value.fp = internal.fp;
				break;
			case Arm64OpType.pstate:
				value.pstate = internal.pstate;
				break;
			case Arm64OpType.sys:
				value.sys = internal.sys;
				break;
			case Arm64OpType.prefetch:
				value.prefetch = internal.prefetch;
				break;
			case Arm64OpType.barrier:
				value.barrier = internal.barrier;
				break;
		}
	}
}

// Instruction structure
struct Arm64InstructionDetail {
	Arm64Cc cc;	// conditional code for this insn
	bool updateFlags;	// does this insn update flags?
	bool writeback;	// does this insn request writeback? 'True' means 'yes'

	Arm64Op[] operands; // operands for this instruction.

	this(cs_arm64 internal){
		cc = internal.cc;
		updateFlags = internal.update_flags;
		writeback = internal.writeback;

		foreach(op; internal.operands[0..internal.op_count])
			operands ~= Arm64Op(op);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Constants
///////////////////////////////////////////////////////////////////////////////

//> ARM64 shift type
enum Arm64ShiftType {
	INVALID = 0,
	LSL = 1,
	MSL = 2,
	LSR = 3,
	ASR = 4,
	ROR = 5,
}

//> ARM64 extender type
enum Arm64Extender {
	INVALID = 0,
	UXTB = 1,
	UXTH = 2,
	UXTW = 3,
	UXTX = 4,
	SXTB = 5,
	SXTH = 6,
	SXTW = 7,
	SXTX = 8,
}

//> ARM64 condition code
enum Arm64Cc {
	INVALID = 0,
	EQ = 1,     // Equal
	NE = 2,     // Not equal:                 Not equal, or unordered
	HS = 3,     // Unsigned higher or same:   >, ==, or unordered
	LO = 4,     // Unsigned lower or same:    Less than
	MI = 5,     // Minus, negative:           Less than
	PL = 6,     // Plus, positive or zero:    >, ==, or unordered
	VS = 7,     // Overflow:                  Unordered
	VC = 8,     // No overflow:               Ordered
	HI = 9,     // Unsigned higher:           Greater than, or unordered
	LS = 10,     // Unsigned lower or same:    Less than or equal
	GE = 11,     // Greater than or equal:     Greater than or equal
	LT = 12,     // Less than:                 Less than, or unordered
	GT = 13,     // Signed greater than:       Greater than
	LE = 14,     // Signed less than or equal: <, ==, or unordered
	AL = 15,     // Always (unconditional):    Always (unconditional)
	NV = 16,     // Always (unconditional):   Always (unconditional)
	// Note the NV exists purely to disassemble 0b1111. Execution
	// is "always".
}

//> System registers
enum Arm64MrsReg {
	//> System registers for MRS
	INVALID           = 0,
	MDCCSR_EL0        = 0x9808, // 10  011  0000  0001  000
	DBGDTRRX_EL0      = 0x9828, // 10  011  0000  0101  000
	MDRAR_EL1         = 0x8080, // 10  000  0001  0000  000
	OSLSR_EL1         = 0x808c, // 10  000  0001  0001  100
	DBGAUTHSTATUS_EL1 = 0x83f6, // 10  000  0111  1110  110
	PMCEID0_EL0       = 0xdce6, // 11  011  1001  1100  110
	PMCEID1_EL0       = 0xdce7, // 11  011  1001  1100  111
	MIDR_EL1          = 0xc000, // 11  000  0000  0000  000
	CCSIDR_EL1        = 0xc800, // 11  001  0000  0000  000
	CLIDR_EL1         = 0xc801, // 11  001  0000  0000  001
	CTR_EL0           = 0xd801, // 11  011  0000  0000  001
	MPIDR_EL1         = 0xc005, // 11  000  0000  0000  101
	REVIDR_EL1        = 0xc006, // 11  000  0000  0000  110
	AIDR_EL1          = 0xc807, // 11  001  0000  0000  111
	DCZID_EL0         = 0xd807, // 11  011  0000  0000  111
	ID_PFR0_EL1       = 0xc008, // 11  000  0000  0001  000
	ID_PFR1_EL1       = 0xc009, // 11  000  0000  0001  001
	ID_DFR0_EL1       = 0xc00a, // 11  000  0000  0001  010
	ID_AFR0_EL1       = 0xc00b, // 11  000  0000  0001  011
	ID_MMFR0_EL1      = 0xc00c, // 11  000  0000  0001  100
	ID_MMFR1_EL1      = 0xc00d, // 11  000  0000  0001  101
	ID_MMFR2_EL1      = 0xc00e, // 11  000  0000  0001  110
	ID_MMFR3_EL1      = 0xc00f, // 11  000  0000  0001  111
	ID_ISAR0_EL1      = 0xc010, // 11  000  0000  0010  000
	ID_ISAR1_EL1      = 0xc011, // 11  000  0000  0010  001
	ID_ISAR2_EL1      = 0xc012, // 11  000  0000  0010  010
	ID_ISAR3_EL1      = 0xc013, // 11  000  0000  0010  011
	ID_ISAR4_EL1      = 0xc014, // 11  000  0000  0010  100
	ID_ISAR5_EL1      = 0xc015, // 11  000  0000  0010  101
	ID_A64PFR0_EL1   = 0xc020, // 11  000  0000  0100  000
	ID_A64PFR1_EL1   = 0xc021, // 11  000  0000  0100  001
	ID_A64DFR0_EL1   = 0xc028, // 11  000  0000  0101  000
	ID_A64DFR1_EL1   = 0xc029, // 11  000  0000  0101  001
	ID_A64AFR0_EL1   = 0xc02c, // 11  000  0000  0101  100
	ID_A64AFR1_EL1   = 0xc02d, // 11  000  0000  0101  101
	ID_A64ISAR0_EL1  = 0xc030, // 11  000  0000  0110  000
	ID_A64ISAR1_EL1  = 0xc031, // 11  000  0000  0110  001
	ID_A64MMFR0_EL1  = 0xc038, // 11  000  0000  0111  000
	ID_A64MMFR1_EL1  = 0xc039, // 11  000  0000  0111  001
	MVFR0_EL1         = 0xc018, // 11  000  0000  0011  000
	MVFR1_EL1         = 0xc019, // 11  000  0000  0011  001
	MVFR2_EL1         = 0xc01a, // 11  000  0000  0011  010
	RVBAR_EL1         = 0xc601, // 11  000  1100  0000  001
	RVBAR_EL2         = 0xe601, // 11  100  1100  0000  001
	RVBAR_EL3         = 0xf601, // 11  110  1100  0000  001
	ISR_EL1           = 0xc608, // 11  000  1100  0001  000
	CNTPCT_EL0        = 0xdf01, // 11  011  1110  0000  001
	CNTVCT_EL0        = 0xdf02,  // 11  011  1110  0000  010

	// Trace registers
	TRCSTATR          = 0x8818, // 10  001  0000  0011  000
	TRCIDR8           = 0x8806, // 10  001  0000  0000  110
	TRCIDR9           = 0x880e, // 10  001  0000  0001  110
	TRCIDR10          = 0x8816, // 10  001  0000  0010  110
	TRCIDR11          = 0x881e, // 10  001  0000  0011  110
	TRCIDR12          = 0x8826, // 10  001  0000  0100  110
	TRCIDR13          = 0x882e, // 10  001  0000  0101  110
	TRCIDR0           = 0x8847, // 10  001  0000  1000  111
	TRCIDR1           = 0x884f, // 10  001  0000  1001  111
	TRCIDR2           = 0x8857, // 10  001  0000  1010  111
	TRCIDR3           = 0x885f, // 10  001  0000  1011  111
	TRCIDR4           = 0x8867, // 10  001  0000  1100  111
	TRCIDR5           = 0x886f, // 10  001  0000  1101  111
	TRCIDR6           = 0x8877, // 10  001  0000  1110  111
	TRCIDR7           = 0x887f, // 10  001  0000  1111  111
	TRCOSLSR          = 0x888c, // 10  001  0001  0001  100
	TRCPDSR           = 0x88ac, // 10  001  0001  0101  100
	TRCDEVAFF0        = 0x8bd6, // 10  001  0111  1010  110
	TRCDEVAFF1        = 0x8bde, // 10  001  0111  1011  110
	TRCLSR            = 0x8bee, // 10  001  0111  1101  110
	TRCAUTHSTATUS     = 0x8bf6, // 10  001  0111  1110  110
	TRCDEVARCH        = 0x8bfe, // 10  001  0111  1111  110
	TRCDEVID          = 0x8b97, // 10  001  0111  0010  111
	TRCDEVTYPE        = 0x8b9f, // 10  001  0111  0011  111
	TRCPIDR4          = 0x8ba7, // 10  001  0111  0100  111
	TRCPIDR5          = 0x8baf, // 10  001  0111  0101  111
	TRCPIDR6          = 0x8bb7, // 10  001  0111  0110  111
	TRCPIDR7          = 0x8bbf, // 10  001  0111  0111  111
	TRCPIDR0          = 0x8bc7, // 10  001  0111  1000  111
	TRCPIDR1          = 0x8bcf, // 10  001  0111  1001  111
	TRCPIDR2          = 0x8bd7, // 10  001  0111  1010  111
	TRCPIDR3          = 0x8bdf, // 10  001  0111  1011  111
	TRCCIDR0          = 0x8be7, // 10  001  0111  1100  111
	TRCCIDR1          = 0x8bef, // 10  001  0111  1101  111
	TRCCIDR2          = 0x8bf7, // 10  001  0111  1110  111
	TRCCIDR3          = 0x8bff, // 10  001  0111  1111  111

	// GICv3 registers
	ICC_IAR1_EL1      = 0xc660, // 11  000  1100  1100  000
	ICC_IAR0_EL1      = 0xc640, // 11  000  1100  1000  000
	ICC_HPPIR1_EL1    = 0xc662, // 11  000  1100  1100  010
	ICC_HPPIR0_EL1    = 0xc642, // 11  000  1100  1000  010
	ICC_RPR_EL1       = 0xc65b, // 11  000  1100  1011  011
	ICH_VTR_EL2       = 0xe659, // 11  100  1100  1011  001
	ICH_EISR_EL2      = 0xe65b, // 11  100  1100  1011  011
	ICH_ELSR_EL2      = 0xe65d, // 11  100  1100  1011  101
}

enum Arm64MsrReg {
	//> System registers for MSR
	DBGDTRTX_EL0      = 0x9828, // 10  011  0000  0101  000
	OSLAR_EL1         = 0x8084, // 10  000  0001  0000  100
	PMSWINC_EL0       = 0xdce4,  // 11  011  1001  1100  100

	// Trace Registers
	TRCOSLAR          = 0x8884, // 10  001  0001  0000  100
	TRCLAR            = 0x8be6, // 10  001  0111  1100  110

	// GICv3 registers
	ICC_EOIR1_EL1     = 0xc661, // 11  000  1100  1100  001
	ICC_EOIR0_EL1     = 0xc641, // 11  000  1100  1000  001
	ICC_DIR_EL1       = 0xc659, // 11  000  1100  1011  001
	ICC_SGI1R_EL1     = 0xc65d, // 11  000  1100  1011  101
	ICC_ASGI1R_EL1    = 0xc65e, // 11  000  1100  1011  110
	ICC_SGI0R_EL1     = 0xc65f, // 11  000  1100  1011  111
}

//> System PState Field (MSR instruction)
enum Arm64PState {
	INVALID = 0,
	SPSEL = 0x05,
	DAIFSET = 0x1e,
	DAIFCLR = 0x1f
}

//> Vector arrangement specifier (for FloatingPoint/Advanced SIMD insn)
enum Arm64Vas {
	INVALID = 0,
	VAS_8B,
	VAS_16B,
	VAS_4H,
	VAS_8H,
	VAS_2S,
	VAS_4S,
	VAS_1D,
	VAS_2D,
	VAS_1Q,
}

//> Vector element size specifier
enum Arm64Vess {
	INVALID = 0,
	B,
	H,
	S,
	D,
}

//> Memory barrier operands
enum Arm64BarrierOp {
	INVALID = 0,
	OSHLD = 0x1,
	OSHST = 0x2,
	OSH =   0x3,
	NSHLD = 0x5,
	NSHST = 0x6,
	NSH =   0x7,
	ISHLD = 0x9,
	ISHST = 0xa,
	ISH =   0xb,
	LD =    0xd,
	ST =    0xe,
	SY =    0xf
}

//> Operand type for instruction's operands
enum Arm64OpType {
	invalid = 0, // = cs_op_invalid (uninitialized).
	reg, // = cs_op_reg (register operand).
	imm, // = cs_op_imm (immediate operand).
	mem, // = cs_op_mem (memory operand).
	fp,  // = cs_op_fp (floating-point operand).
	cimm = 64, // c-immediate
	reg_mrs, // mrs register operand.
	reg_msr, // msr register operand.
	pstate, // pstate operand.
	sys, // sys operand for ic/dc/at/tlbi instructions.
	prefetch, // prefetch operand (prfm).
	barrier, // memory barrier operand (isb/dmb/dsb instructions).
}

//> TLBI operations
enum Arm64TlbiOp {
	INVALID = 0,
	VMALLE1IS,
	VAE1IS,
	ASIDE1IS,
	VAAE1IS,
	VALE1IS,
	VAALE1IS,
	ALLE2IS,
	VAE2IS,
	ALLE1IS,
	VALE2IS,
	VMALLS12E1IS,
	ALLE3IS,
	VAE3IS,
	VALE3IS,
	IPAS2E1IS,
	IPAS2LE1IS,
	IPAS2E1,
	IPAS2LE1,
	VMALLE1,
	VAE1,
	ASIDE1,
	VAAE1,
	VALE1,
	VAALE1,
	ALLE2,
	VAE2,
	ALLE1,
	VALE2,
	VMALLS12E1,
	ALLE3,
	VAE3,
	VALE3,
}

//> AT operations
enum Arm64AtOp {
	S1E1R,
	S1E1W,
	S1E0R,
	S1E0W,
	S1E2R,
	S1E2W,
	S12E1R,
	S12E1W,
	S12E0R,
	S12E0W,
	S1E3R,
	S1E3W,
}

//> DC operations
enum Arm64DcOp {
	INVALID = 0,
	ZVA,
	IVAC,
	ISW,
	CVAC,
	CSW,
	CVAU,
	CIVAC,
	CISW,
}

//> IC operations
enum Arm64IcOp {
	INVALID = 0,
	IALLUIS,
	IALLU,
	IVAU,
}

//> Prefetch operations (PRFM)
enum Arm64PrefetchOp {
	INVALID = 0,
	PLDL1KEEP = 0x00 + 1,
	PLDL1STRM = 0x01 + 1,
	PLDL2KEEP = 0x02 + 1,
	PLDL2STRM = 0x03 + 1,
	PLDL3KEEP = 0x04 + 1,
	PLDL3STRM = 0x05 + 1,
	PLIL1KEEP = 0x08 + 1,
	PLIL1STRM = 0x09 + 1,
	PLIL2KEEP = 0x0a + 1,
	PLIL2STRM = 0x0b + 1,
	PLIL3KEEP = 0x0c + 1,
	PLIL3STRM = 0x0d + 1,
	PSTL1KEEP = 0x10 + 1,
	PSTL1STRM = 0x11 + 1,
	PSTL2KEEP = 0x12 + 1,
	PSTL2STRM = 0x13 + 1,
	PSTL3KEEP = 0x14 + 1,
	PSTL3STRM = 0x15 + 1,
}

//> ARM64 registers
enum Arm64Register {
	INVALID = 0,

	X29,
	X30,
	NZCV,
	SP,
	WSP,
	WZR,
	XZR,
	B0,
	B1,
	B2,
	B3,
	B4,
	B5,
	B6,
	B7,
	B8,
	B9,
	B10,
	B11,
	B12,
	B13,
	B14,
	B15,
	B16,
	B17,
	B18,
	B19,
	B20,
	B21,
	B22,
	B23,
	B24,
	B25,
	B26,
	B27,
	B28,
	B29,
	B30,
	B31,
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
	H0,
	H1,
	H2,
	H3,
	H4,
	H5,
	H6,
	H7,
	H8,
	H9,
	H10,
	H11,
	H12,
	H13,
	H14,
	H15,
	H16,
	H17,
	H18,
	H19,
	H20,
	H21,
	H22,
	H23,
	H24,
	H25,
	H26,
	H27,
	H28,
	H29,
	H30,
	H31,
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
	Q16,
	Q17,
	Q18,
	Q19,
	Q20,
	Q21,
	Q22,
	Q23,
	Q24,
	Q25,
	Q26,
	Q27,
	Q28,
	Q29,
	Q30,
	Q31,
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
	W0,
	W1,
	W2,
	W3,
	W4,
	W5,
	W6,
	W7,
	W8,
	W9,
	W10,
	W11,
	W12,
	W13,
	W14,
	W15,
	W16,
	W17,
	W18,
	W19,
	W20,
	W21,
	W22,
	W23,
	W24,
	W25,
	W26,
	W27,
	W28,
	W29,
	W30,
	X0,
	X1,
	X2,
	X3,
	X4,
	X5,
	X6,
	X7,
	X8,
	X9,
	X10,
	X11,
	X12,
	X13,
	X14,
	X15,
	X16,
	X17,
	X18,
	X19,
	X20,
	X21,
	X22,
	X23,
	X24,
	X25,
	X26,
	X27,
	X28,

	V0,
	V1,
	V2,
	V3,
	V4,
	V5,
	V6,
	V7,
	V8,
	V9,
	V10,
	V11,
	V12,
	V13,
	V14,
	V15,
	V16,
	V17,
	V18,
	V19,
	V20,
	V21,
	V22,
	V23,
	V24,
	V25,
	V26,
	V27,
	V28,
	V29,
	V30,
	V31,

	//> alias registers
	IP1 = X16,
	IP0 = X17,
	FP = X29,
	LR = X30,
}

//> ARM64 instruction
enum Arm64InstructionId {
	INVALID = 0,

	ABS,
	ADC,
	ADDHN,
	ADDHN2,
	ADDP,
	ADD,
	ADDV,
	ADR,
	ADRP,
	AESD,
	AESE,
	AESIMC,
	AESMC,
	AND,
	ASR,
	B,
	BFM,
	BIC,
	BIF,
	BIT,
	BL,
	BLR,
	BR,
	BRK,
	BSL,
	CBNZ,
	CBZ,
	CCMN,
	CCMP,
	CLREX,
	CLS,
	CLZ,
	CMEQ,
	CMGE,
	CMGT,
	CMHI,
	CMHS,
	CMLE,
	CMLT,
	CMTST,
	CNT,
	MOV,
	CRC32B,
	CRC32CB,
	CRC32CH,
	CRC32CW,
	CRC32CX,
	CRC32H,
	CRC32W,
	CRC32X,
	CSEL,
	CSINC,
	CSINV,
	CSNEG,
	DCPS1,
	DCPS2,
	DCPS3,
	DMB,
	DRPS,
	DSB,
	DUP,
	EON,
	EOR,
	ERET,
	EXTR,
	EXT,
	FABD,
	FABS,
	FACGE,
	FACGT,
	FADD,
	FADDP,
	FCCMP,
	FCCMPE,
	FCMEQ,
	FCMGE,
	FCMGT,
	FCMLE,
	FCMLT,
	FCMP,
	FCMPE,
	FCSEL,
	FCVTAS,
	FCVTAU,
	FCVT,
	FCVTL,
	FCVTL2,
	FCVTMS,
	FCVTMU,
	FCVTNS,
	FCVTNU,
	FCVTN,
	FCVTN2,
	FCVTPS,
	FCVTPU,
	FCVTXN,
	FCVTXN2,
	FCVTZS,
	FCVTZU,
	FDIV,
	FMADD,
	FMAX,
	FMAXNM,
	FMAXNMP,
	FMAXNMV,
	FMAXP,
	FMAXV,
	FMIN,
	FMINNM,
	FMINNMP,
	FMINNMV,
	FMINP,
	FMINV,
	FMLA,
	FMLS,
	FMOV,
	FMSUB,
	FMUL,
	FMULX,
	FNEG,
	FNMADD,
	FNMSUB,
	FNMUL,
	FRECPE,
	FRECPS,
	FRECPX,
	FRINTA,
	FRINTI,
	FRINTM,
	FRINTN,
	FRINTP,
	FRINTX,
	FRINTZ,
	FRSQRTE,
	FRSQRTS,
	FSQRT,
	FSUB,
	HINT,
	HLT,
	HVC,
	INS,

	ISB,
	LD1,
	LD1R,
	LD2R,
	LD2,
	LD3R,
	LD3,
	LD4,
	LD4R,

	LDARB,
	LDARH,
	LDAR,
	LDAXP,
	LDAXRB,
	LDAXRH,
	LDAXR,
	LDNP,
	LDP,
	LDPSW,
	LDRB,
	LDR,
	LDRH,
	LDRSB,
	LDRSH,
	LDRSW,
	LDTRB,
	LDTRH,
	LDTRSB,

	LDTRSH,
	LDTRSW,
	LDTR,
	LDURB,
	LDUR,
	LDURH,
	LDURSB,
	LDURSH,
	LDURSW,
	LDXP,
	LDXRB,
	LDXRH,
	LDXR,
	LSL,
	LSR,
	MADD,
	MLA,
	MLS,
	MOVI,
	MOVK,
	MOVN,
	MOVZ,
	MRS,
	MSR,
	MSUB,
	MUL,
	MVNI,
	NEG,
	NOT,
	ORN,
	ORR,
	PMULL2,
	PMULL,
	PMUL,
	PRFM,
	PRFUM,
	RADDHN,
	RADDHN2,
	RBIT,
	RET,
	REV16,
	REV32,
	REV64,
	REV,
	ROR,
	RSHRN2,
	RSHRN,
	RSUBHN,
	RSUBHN2,
	SABAL2,
	SABAL,

	SABA,
	SABDL2,
	SABDL,
	SABD,
	SADALP,
	SADDLP,
	SADDLV,
	SADDL2,
	SADDL,
	SADDW2,
	SADDW,
	SBC,
	SBFM,
	SCVTF,
	SDIV,
	SHA1C,
	SHA1H,
	SHA1M,
	SHA1P,
	SHA1SU0,
	SHA1SU1,
	SHA256H2,
	SHA256H,
	SHA256SU0,
	SHA256SU1,
	SHADD,
	SHLL2,
	SHLL,
	SHL,
	SHRN2,
	SHRN,
	SHSUB,
	SLI,
	SMADDL,
	SMAXP,
	SMAXV,
	SMAX,
	SMC,
	SMINP,
	SMINV,
	SMIN,
	SMLAL2,
	SMLAL,
	SMLSL2,
	SMLSL,
	SMOV,
	SMSUBL,
	SMULH,
	SMULL2,
	SMULL,
	SQABS,
	SQADD,
	SQDMLAL,
	SQDMLAL2,
	SQDMLSL,
	SQDMLSL2,
	SQDMULH,
	SQDMULL,
	SQDMULL2,
	SQNEG,
	SQRDMULH,
	SQRSHL,
	SQRSHRN,
	SQRSHRN2,
	SQRSHRUN,
	SQRSHRUN2,
	SQSHLU,
	SQSHL,
	SQSHRN,
	SQSHRN2,
	SQSHRUN,
	SQSHRUN2,
	SQSUB,
	SQXTN2,
	SQXTN,
	SQXTUN2,
	SQXTUN,
	SRHADD,
	SRI,
	SRSHL,
	SRSHR,
	SRSRA,
	SSHLL2,
	SSHLL,
	SSHL,
	SSHR,
	SSRA,
	SSUBL2,
	SSUBL,
	SSUBW2,
	SSUBW,
	ST1,
	ST2,
	ST3,
	ST4,
	STLRB,
	STLRH,
	STLR,
	STLXP,
	STLXRB,
	STLXRH,
	STLXR,
	STNP,
	STP,
	STRB,
	STR,
	STRH,
	STTRB,
	STTRH,
	STTR,
	STURB,
	STUR,
	STURH,
	STXP,
	STXRB,
	STXRH,
	STXR,
	SUBHN,
	SUBHN2,
	SUB,
	SUQADD,
	SVC,
	SYSL,
	SYS,
	TBL,
	TBNZ,
	TBX,
	TBZ,
	TRN1,
	TRN2,
	UABAL2,
	UABAL,
	UABA,
	UABDL2,
	UABDL,
	UABD,
	UADALP,
	UADDLP,
	UADDLV,
	UADDL2,
	UADDL,
	UADDW2,
	UADDW,
	UBFM,
	UCVTF,
	UDIV,
	UHADD,
	UHSUB,
	UMADDL,
	UMAXP,
	UMAXV,
	UMAX,
	UMINP,
	UMINV,
	UMIN,
	UMLAL2,
	UMLAL,
	UMLSL2,
	UMLSL,
	UMOV,
	UMSUBL,
	UMULH,
	UMULL2,
	UMULL,
	UQADD,
	UQRSHL,
	UQRSHRN,
	UQRSHRN2,
	UQSHL,
	UQSHRN,
	UQSHRN2,
	UQSUB,
	UQXTN2,
	UQXTN,
	URECPE,
	URHADD,
	URSHL,
	URSHR,
	URSQRTE,
	URSRA,
	USHLL2,
	USHLL,
	USHL,
	USHR,
	USQADD,
	USRA,
	USUBL2,
	USUBL,
	USUBW2,
	USUBW,
	UZP1,
	UZP2,
	XTN2,
	XTN,
	ZIP1,
	ZIP2,

	// alias insn
	MNEG,
	UMNEGL,
	SMNEGL,
	NOP,
	YIELD,
	WFE,
	WFI,
	SEV,
	SEVL,
	NGC,
	SBFIZ,
	UBFIZ,
	SBFX,
	UBFX,
	BFI,
	BFXIL,
	CMN,
	MVN,
	TST,
	CSET,
	CINC,
	CSETM,
	CINV,
	CNEG,
	SXTB,
	SXTH,
	SXTW,
	CMP,
	UXTB,
	UXTH,
	UXTW,
	IC,
	DC,
	AT,
	TLBI
}

//> Group of ARM64 instructions
enum Arm64InstructionGroup {
	INVALID = 0, // = CS_GRP_INVALID

	//> Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	JUMP,	// = CS_GRP_JUMP

	//> Architecture-specific groups
	CRYPTO = 128,
	FPARMV8,
	NEON,
	CRC
}