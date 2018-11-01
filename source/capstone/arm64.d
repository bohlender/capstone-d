/// Types and constants of ARM64 architecture
module capstone.arm64;

import std.variant;
import std.exception: enforce;

import capstone.internal;
import capstone.utils;

/** Instruction's operand referring to memory

This is associated with the `Arm64OpType.mem` operand type
*/
struct Arm64OpMem {
	Arm64Register base;	 /// Base register
	Arm64Register index; /// Index register
	int disp;			 /// displacement/offset value
}

/// Optional shift
struct Arm64Shift{
	Arm64ShiftType type; /// Type of shift
	uint value;			 /// value (constant or register) to shift by
}

/// Tagged union of possible operand values
alias Arm64OperandValue = TaggedUnion!(Arm64Register, "reg", long, "imm", double, "fp", Arm64OpMem, "mem", Arm64PState, "pstate", uint, "sys", Arm64PrefetchOp, "prefetch", Arm64BarrierOp, "barrier");

/// Instruction operand
struct Arm64Op {
	int vectorIndex;  		 /// Vector index for some vector operands (or -1 if irrelevant)
	Arm64Vas vas;	   		 /// Vector arrangement specifier
	Arm64Vess vess;	  		 /// Vector element size specifier
	Arm64Shift shift; 		 /// Potential shifting of operand
	Arm64Extender ext;		 /// Extender type of this operand
	Arm64OpType type; 		 /// Operand type
	Arm64OperandValue value; /// Operand value of type `type`
	alias value this; 		 /// Conventient access to value (as in original bindings)

    package this(cs_arm64_op internal){
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

/// ARM64-specific information about an instruction
struct Arm64InstructionDetail {
	Arm64Cc cc;		  	/// Conditional code for this instruction
	bool updateFlags; 	/// Does this instruction update flags?
	bool writeback;	  	/// Does this instruction request writeback?

	Arm64Op[] operands; /// Operands for this instruction.

    package this(cs_arch_detail arch_detail){
		this(arch_detail.arm64);
	}
    package this(cs_arm64 internal){
		cc = internal.cc;
		updateFlags = internal.update_flags;
		writeback = internal.writeback;

		foreach(op; internal.operands[0..internal.op_count])
			operands ~= Arm64Op(op);
	}
}

//=============================================================================
// Constants
//=============================================================================

/// ARM64 shift type
enum Arm64ShiftType {
	invalid = 0, /// Invalid
	lsl = 1,	 /// Logical shift left
	msl = 2,	 /// Move shift left
	lsr = 3,	 /// Logical shift right
	asr = 4,	 /// Arithmetic shift right
	ror = 5,	 /// Rotate right
}

/// ARM64 extender type
enum Arm64Extender {
	invalid = 0,
	uxtb = 1,
	uxth = 2,
	uxtw = 3,
	uxtx = 4,
	sxtb = 5,
	sxth = 6,
	sxtw = 7,
	sxtx = 8,
}

/// ARM64 condition code
enum Arm64Cc {
	invalid = 0,
	eq = 1,      /// Equal
	ne = 2,      /// Not equal:                 Not equal, or unordered
	hs = 3,      /// Unsigned higher or same:   >, ==, or unordered
	lo = 4,      /// Unsigned lower or same:    Less than
	mi = 5,      /// Minus, negative:           Less than
	pl = 6,      /// Plus, positive or zero:    >, ==, or unordered
	vs = 7,      /// Overflow:                  Unordered
	vc = 8,      /// No overflow:               Ordered
	hi = 9,      /// Unsigned higher:           Greater than, or unordered
	ls = 10,     /// Unsigned lower or same:    Less than or equal
	ge = 11,     /// Greater than or equal:     Greater than or equal
	lt = 12,     /// Less than:                 Less than, or unordered
	gt = 13,     /// Signed greater than:       Greater than
	le = 14,     /// Signed less than or equal: <, ==, or unordered
	al = 15,     /// Always (unconditional):    Always (unconditional)

	nv = 16,     /// Always (unconditional):    Always (unconditional) - exists purely to disassemble 0b1111
}

/// System registers for MRS
enum Arm64MrsReg {
	invalid           = 0,
	mdccsr_el0        = 0x9808, // 10  011  0000  0001  000
	dbgdtrrx_el0      = 0x9828, // 10  011  0000  0101  000
	mdrar_el1         = 0x8080, // 10  000  0001  0000  000
	oslsr_el1         = 0x808c, // 10  000  0001  0001  100
	dbgauthstatus_el1 = 0x83f6, // 10  000  0111  1110  110
	pmceid0_el0       = 0xdce6, // 11  011  1001  1100  110
	pmceid1_el0       = 0xdce7, // 11  011  1001  1100  111
	midr_el1          = 0xc000, // 11  000  0000  0000  000
	ccsidr_el1        = 0xc800, // 11  001  0000  0000  000
	clidr_el1         = 0xc801, // 11  001  0000  0000  001
	ctr_el0           = 0xd801, // 11  011  0000  0000  001
	mpidr_el1         = 0xc005, // 11  000  0000  0000  101
	revidr_el1        = 0xc006, // 11  000  0000  0000  110
	aidr_el1          = 0xc807, // 11  001  0000  0000  111
	dczid_el0         = 0xd807, // 11  011  0000  0000  111
	id_pfr0_el1       = 0xc008, // 11  000  0000  0001  000
	id_pfr1_el1       = 0xc009, // 11  000  0000  0001  001
	id_dfr0_el1       = 0xc00a, // 11  000  0000  0001  010
	id_afr0_el1       = 0xc00b, // 11  000  0000  0001  011
	id_mmfr0_el1      = 0xc00c, // 11  000  0000  0001  100
	id_mmfr1_el1      = 0xc00d, // 11  000  0000  0001  101
	id_mmfr2_el1      = 0xc00e, // 11  000  0000  0001  110
	id_mmfr3_el1      = 0xc00f, // 11  000  0000  0001  111
	id_isar0_el1      = 0xc010, // 11  000  0000  0010  000
	id_isar1_el1      = 0xc011, // 11  000  0000  0010  001
	id_isar2_el1      = 0xc012, // 11  000  0000  0010  010
	id_isar3_el1      = 0xc013, // 11  000  0000  0010  011
	id_isar4_el1      = 0xc014, // 11  000  0000  0010  100
	id_isar5_el1      = 0xc015, // 11  000  0000  0010  101
	id_a64pfr0_el1    = 0xc020, // 11  000  0000  0100  000
	id_a64pfr1_el1    = 0xc021, // 11  000  0000  0100  001
	id_a64dfr0_el1    = 0xc028, // 11  000  0000  0101  000
	id_a64dfr1_el1    = 0xc029, // 11  000  0000  0101  001
	id_a64afr0_el1    = 0xc02c, // 11  000  0000  0101  100
	id_a64afr1_el1    = 0xc02d, // 11  000  0000  0101  101
	id_a64isar0_el1   = 0xc030, // 11  000  0000  0110  000
	id_a64isar1_el1   = 0xc031, // 11  000  0000  0110  001
	id_a64mmfr0_el1   = 0xc038, // 11  000  0000  0111  000
	id_a64mmfr1_el1   = 0xc039, // 11  000  0000  0111  001
	mvfr0_el1         = 0xc018, // 11  000  0000  0011  000
	mvfr1_el1         = 0xc019, // 11  000  0000  0011  001
	mvfr2_el1         = 0xc01a, // 11  000  0000  0011  010
	rvbar_el1         = 0xc601, // 11  000  1100  0000  001
	rvbar_el2         = 0xe601, // 11  100  1100  0000  001
	rvbar_el3         = 0xf601, // 11  110  1100  0000  001
	isr_el1           = 0xc608, // 11  000  1100  0001  000
	cntpct_el0        = 0xdf01, // 11  011  1110  0000  001
	cntvct_el0        = 0xdf02, // 11  011  1110  0000  010

	// Trace registers
	trcstatr          = 0x8818, // 10  001  0000  0011  000
	trcidr8           = 0x8806, // 10  001  0000  0000  110
	trcidr9           = 0x880e, // 10  001  0000  0001  110
	trcidr10          = 0x8816, // 10  001  0000  0010  110
	trcidr11          = 0x881e, // 10  001  0000  0011  110
	trcidr12          = 0x8826, // 10  001  0000  0100  110
	trcidr13          = 0x882e, // 10  001  0000  0101  110
	trcidr0           = 0x8847, // 10  001  0000  1000  111
	trcidr1           = 0x884f, // 10  001  0000  1001  111
	trcidr2           = 0x8857, // 10  001  0000  1010  111
	trcidr3           = 0x885f, // 10  001  0000  1011  111
	trcidr4           = 0x8867, // 10  001  0000  1100  111
	trcidr5           = 0x886f, // 10  001  0000  1101  111
	trcidr6           = 0x8877, // 10  001  0000  1110  111
	trcidr7           = 0x887f, // 10  001  0000  1111  111
	trcoslsr          = 0x888c, // 10  001  0001  0001  100
	trcpdsr           = 0x88ac, // 10  001  0001  0101  100
	trcdevaff0        = 0x8bd6, // 10  001  0111  1010  110
	trcdevaff1        = 0x8bde, // 10  001  0111  1011  110
	trclsr            = 0x8bee, // 10  001  0111  1101  110
	trcauthstatus     = 0x8bf6, // 10  001  0111  1110  110
	trcdevarch        = 0x8bfe, // 10  001  0111  1111  110
	trcdevid          = 0x8b97, // 10  001  0111  0010  111
	trcdevtype        = 0x8b9f, // 10  001  0111  0011  111
	trcpidr4          = 0x8ba7, // 10  001  0111  0100  111
	trcpidr5          = 0x8baf, // 10  001  0111  0101  111
	trcpidr6          = 0x8bb7, // 10  001  0111  0110  111
	trcpidr7          = 0x8bbf, // 10  001  0111  0111  111
	trcpidr0          = 0x8bc7, // 10  001  0111  1000  111
	trcpidr1          = 0x8bcf, // 10  001  0111  1001  111
	trcpidr2          = 0x8bd7, // 10  001  0111  1010  111
	trcpidr3          = 0x8bdf, // 10  001  0111  1011  111
	trccidr0          = 0x8be7, // 10  001  0111  1100  111
	trccidr1          = 0x8bef, // 10  001  0111  1101  111
	trccidr2          = 0x8bf7, // 10  001  0111  1110  111
	trccidr3          = 0x8bff, // 10  001  0111  1111  111

	// GICv3 registers
	icc_iar1_el1      = 0xc660, // 11  000  1100  1100  000
	icc_iar0_el1      = 0xc640, // 11  000  1100  1000  000
	icc_hppir1_el1    = 0xc662, // 11  000  1100  1100  010
	icc_hppir0_el1    = 0xc642, // 11  000  1100  1000  010
	icc_rpr_el1       = 0xc65b, // 11  000  1100  1011  011
	ich_vtr_el2       = 0xe659, // 11  100  1100  1011  001
	ich_eisr_el2      = 0xe65b, // 11  100  1100  1011  011
	ich_elsr_el2      = 0xe65d, // 11  100  1100  1011  101
}

/// System registers for MSR
enum Arm64MsrReg {
	dbgdtrtx_el0      = 0x9828, // 10  011  0000  0101  000
	oslar_el1         = 0x8084, // 10  000  0001  0000  100
	pmswinc_el0       = 0xdce4, // 11  011  1001  1100  100

	// Trace registers
	trcoslar          = 0x8884, // 10  001  0001  0000  100
	trclar            = 0x8be6, // 10  001  0111  1100  110

	// GICv3 registers
	icc_eoir1_el1     = 0xc661, // 11  000  1100  1100  001
	icc_eoir0_el1     = 0xc641, // 11  000  1100  1000  001
	icc_dir_el1       = 0xc659, // 11  000  1100  1011  001
	icc_sgi1r_el1     = 0xc65d, // 11  000  1100  1011  101
	icc_asgi1r_el1    = 0xc65e, // 11  000  1100  1011  110
	icc_sgi0r_el1     = 0xc65f, // 11  000  1100  1011  111
}

/// System PState Field (MSR instruction)
enum Arm64PState {
	invalid = 0,
	spsel   = 0x05,
	daifset = 0x1e,
	daifclr = 0x1f
}

/// Vector arrangement specifier (for FloatingPoint/Advanced SIMD instructions)
enum Arm64Vas {
	invalid = 0,
	vas_8b,
	vas_16b,
	vas_4h,
	vas_8h,
	vas_2s,
	vas_4s,
	vas_1d,
	vas_2d,
	vas_1q,
}

/// Vector element size specifier
enum Arm64Vess {
	invalid = 0,
	b,
	h,
	s,
	d,
}

/// Memory barrier operands
enum Arm64BarrierOp {
	invalid = 0,
	oshld = 0x1,
	oshst = 0x2,
	osh =   0x3,
	nshld = 0x5,
	nshst = 0x6,
	nsh =   0x7,
	ishld = 0x9,
	ishst = 0xa,
	ish =   0xb,
	ld =    0xd,
	st =    0xe,
	sy =    0xf
}

/// Operand type for instruction's operands
enum Arm64OpType {
	invalid = 0,  /// Invalid
	reg, 		  /// Register operand (`Arm64Register`)
	imm, 		  /// Immediate operand (`long`)
	mem, 		  /// Memory operand (`Arm64OpMem`)
	fp,  		  /// Floating-point operand (`double`)
	cimm = 64, 	  /// C-Immediate (`long`)
	reg_mrs, 	  /// MRS register operand (`Arm64Register`)
	reg_msr,      /// MSR register operand (`Arm64Register`)
	pstate, 	  /// P-state operand (`Arm64PState`)
	sys, 		  /// Sys operand for ic/dc/at/tlbi instructions (`uint`)
	prefetch, 	  /// Prefetch operand prfm (`Arm64PrefetchOp`)
	barrier,	  /// Memory barrier operand for isb/dmb/dsb instructions (`Arm64BarrierOp`)
}

/// TLBI operations
enum Arm64TlbiOp {
	invalid = 0,
	vmalle1is,
	vae1is,
	aside1is,
	vaae1is,
	vale1is,
	vaale1is,
	alle2is,
	vae2is,
	alle1is,
	vale2is,
	vmalls12e1is,
	alle3is,
	vae3is,
	vale3is,
	ipas2e1is,
	ipas2le1is,
	ipas2e1,
	ipas2le1,
	vmalle1,
	vae1,
	aside1,
	vaae1,
	vale1,
	vaale1,
	alle2,
	vae2,
	alle1,
	vale2,
	vmalls12e1,
	alle3,
	vae3,
	vale3,
}

/// AT operations
enum Arm64AtOp {
	s1e1r,
	s1e1w,
	s1e0r,
	s1e0w,
	s1e2r,
	s1e2w,
	s12e1r,
	s12e1w,
	s12e0r,
	s12e0w,
	s1e3r,
	s1e3w,
}

/// DC operations
enum Arm64DcOp {
	invalid = 0,
	zva,
	ivac,
	isw,
	cvac,
	csw,
	cvau,
	civac,
	cisw,
}

/// IC operations
enum Arm64IcOp {
	invalid = 0,
	ialluis,
	iallu,
	ivau,
}

/// Prefetch operations (PRFM)
enum Arm64PrefetchOp {
	invalid = 0,
	pldl1keep = 0x00 + 1,
	pldl1strm = 0x01 + 1,
	pldl2keep = 0x02 + 1,
	pldl2strm = 0x03 + 1,
	pldl3keep = 0x04 + 1,
	pldl3strm = 0x05 + 1,
	plil1keep = 0x08 + 1,
	plil1strm = 0x09 + 1,
	plil2keep = 0x0a + 1,
	plil2strm = 0x0b + 1,
	plil3keep = 0x0c + 1,
	plil3strm = 0x0d + 1,
	pstl1keep = 0x10 + 1,
	pstl1strm = 0x11 + 1,
	pstl2keep = 0x12 + 1,
	pstl2strm = 0x13 + 1,
	pstl3keep = 0x14 + 1,
	pstl3strm = 0x15 + 1,
}

/// ARM64 registers
enum Arm64Register {
	invalid = 0,

	x29,
	x30,
	nzcv,
	sp,
	wsp,
	wzr,
	xzr,
	b0,
	b1,
	b2,
	b3,
	b4,
	b5,
	b6,
	b7,
	b8,
	b9,
	b10,
	b11,
	b12,
	b13,
	b14,
	b15,
	b16,
	b17,
	b18,
	b19,
	b20,
	b21,
	b22,
	b23,
	b24,
	b25,
	b26,
	b27,
	b28,
	b29,
	b30,
	b31,
	d0,
	d1,
	d2,
	d3,
	d4,
	d5,
	d6,
	d7,
	d8,
	d9,
	d10,
	d11,
	d12,
	d13,
	d14,
	d15,
	d16,
	d17,
	d18,
	d19,
	d20,
	d21,
	d22,
	d23,
	d24,
	d25,
	d26,
	d27,
	d28,
	d29,
	d30,
	d31,
	h0,
	h1,
	h2,
	h3,
	h4,
	h5,
	h6,
	h7,
	h8,
	h9,
	h10,
	h11,
	h12,
	h13,
	h14,
	h15,
	h16,
	h17,
	h18,
	h19,
	h20,
	h21,
	h22,
	h23,
	h24,
	h25,
	h26,
	h27,
	h28,
	h29,
	h30,
	h31,
	q0,
	q1,
	q2,
	q3,
	q4,
	q5,
	q6,
	q7,
	q8,
	q9,
	q10,
	q11,
	q12,
	q13,
	q14,
	q15,
	q16,
	q17,
	q18,
	q19,
	q20,
	q21,
	q22,
	q23,
	q24,
	q25,
	q26,
	q27,
	q28,
	q29,
	q30,
	q31,
	s0,
	s1,
	s2,
	s3,
	s4,
	s5,
	s6,
	s7,
	s8,
	s9,
	s10,
	s11,
	s12,
	s13,
	s14,
	s15,
	s16,
	s17,
	s18,
	s19,
	s20,
	s21,
	s22,
	s23,
	s24,
	s25,
	s26,
	s27,
	s28,
	s29,
	s30,
	s31,
	w0,
	w1,
	w2,
	w3,
	w4,
	w5,
	w6,
	w7,
	w8,
	w9,
	w10,
	w11,
	w12,
	w13,
	w14,
	w15,
	w16,
	w17,
	w18,
	w19,
	w20,
	w21,
	w22,
	w23,
	w24,
	w25,
	w26,
	w27,
	w28,
	w29,
	w30,
	x0,
	x1,
	x2,
	x3,
	x4,
	x5,
	x6,
	x7,
	x8,
	x9,
	x10,
	x11,
	x12,
	x13,
	x14,
	x15,
	x16,
	x17,
	x18,
	x19,
	x20,
	x21,
	x22,
	x23,
	x24,
	x25,
	x26,
	x27,
	x28,

	v0,
	v1,
	v2,
	v3,
	v4,
	v5,
	v6,
	v7,
	v8,
	v9,
	v10,
	v11,
	v12,
	v13,
	v14,
	v15,
	v16,
	v17,
	v18,
	v19,
	v20,
	v21,
	v22,
	v23,
	v24,
	v25,
	v26,
	v27,
	v28,
	v29,
	v30,
	v31,

	// Alias registers
	ip1 = x16,
	ip0 = x17,
	fp = x29,
	lr = x30,
}

/// ARM64 instruction
enum Arm64InstructionId {
	invalid = 0,

	abs,
	adc,
	addhn,
	addhn2,
	addp,
	add,
	addv,
	adr,
	adrp,
	aesd,
	aese,
	aesimc,
	aesmc,
	and,
	asr,
	b,
	bfm,
	bic,
	bif,
	bit,
	bl,
	blr,
	br,
	brk,
	bsl,
	cbnz,
	cbz,
	ccmn,
	ccmp,
	clrex,
	cls,
	clz,
	cmeq,
	cmge,
	cmgt,
	cmhi,
	cmhs,
	cmle,
	cmlt,
	cmtst,
	cnt,
	mov,
	crc32b,
	crc32cb,
	crc32ch,
	crc32cw,
	crc32cx,
	crc32h,
	crc32w,
	crc32x,
	csel,
	csinc,
	csinv,
	csneg,
	dcps1,
	dcps2,
	dcps3,
	dmb,
	drps,
	dsb,
	dup,
	eon,
	eor,
	eret,
	extr,
	ext,
	fabd,
	fabs,
	facge,
	facgt,
	fadd,
	faddp,
	fccmp,
	fccmpe,
	fcmeq,
	fcmge,
	fcmgt,
	fcmle,
	fcmlt,
	fcmp,
	fcmpe,
	fcsel,
	fcvtas,
	fcvtau,
	fcvt,
	fcvtl,
	fcvtl2,
	fcvtms,
	fcvtmu,
	fcvtns,
	fcvtnu,
	fcvtn,
	fcvtn2,
	fcvtps,
	fcvtpu,
	fcvtxn,
	fcvtxn2,
	fcvtzs,
	fcvtzu,
	fdiv,
	fmadd,
	fmax,
	fmaxnm,
	fmaxnmp,
	fmaxnmv,
	fmaxp,
	fmaxv,
	fmin,
	fminnm,
	fminnmp,
	fminnmv,
	fminp,
	fminv,
	fmla,
	fmls,
	fmov,
	fmsub,
	fmul,
	fmulx,
	fneg,
	fnmadd,
	fnmsub,
	fnmul,
	frecpe,
	frecps,
	frecpx,
	frinta,
	frinti,
	frintm,
	frintn,
	frintp,
	frintx,
	frintz,
	frsqrte,
	frsqrts,
	fsqrt,
	fsub,
	hint,
	hlt,
	hvc,
	ins,

	isb,
	ld1,
	ld1r,
	ld2r,
	ld2,
	ld3r,
	ld3,
	ld4,
	ld4r,

	ldarb,
	ldarh,
	ldar,
	ldaxp,
	ldaxrb,
	ldaxrh,
	ldaxr,
	ldnp,
	ldp,
	ldpsw,
	ldrb,
	ldr,
	ldrh,
	ldrsb,
	ldrsh,
	ldrsw,
	ldtrb,
	ldtrh,
	ldtrsb,

	ldtrsh,
	ldtrsw,
	ldtr,
	ldurb,
	ldur,
	ldurh,
	ldursb,
	ldursh,
	ldursw,
	ldxp,
	ldxrb,
	ldxrh,
	ldxr,
	lsl,
	lsr,
	madd,
	mla,
	mls,
	movi,
	movk,
	movn,
	movz,
	mrs,
	msr,
	msub,
	mul,
	mvni,
	neg,
	not,
	orn,
	orr,
	pmull2,
	pmull,
	pmul,
	prfm,
	prfum,
	raddhn,
	raddhn2,
	rbit,
	ret,
	rev16,
	rev32,
	rev64,
	rev,
	ror,
	rshrn2,
	rshrn,
	rsubhn,
	rsubhn2,
	sabal2,
	sabal,

	saba,
	sabdl2,
	sabdl,
	sabd,
	sadalp,
	saddlp,
	saddlv,
	saddl2,
	saddl,
	saddw2,
	saddw,
	sbc,
	sbfm,
	scvtf,
	sdiv,
	sha1c,
	sha1h,
	sha1m,
	sha1p,
	sha1su0,
	sha1su1,
	sha256h2,
	sha256h,
	sha256su0,
	sha256su1,
	shadd,
	shll2,
	shll,
	shl,
	shrn2,
	shrn,
	shsub,
	sli,
	smaddl,
	smaxp,
	smaxv,
	smax,
	smc,
	sminp,
	sminv,
	smin,
	smlal2,
	smlal,
	smlsl2,
	smlsl,
	smov,
	smsubl,
	smulh,
	smull2,
	smull,
	sqabs,
	sqadd,
	sqdmlal,
	sqdmlal2,
	sqdmlsl,
	sqdmlsl2,
	sqdmulh,
	sqdmull,
	sqdmull2,
	sqneg,
	sqrdmulh,
	sqrshl,
	sqrshrn,
	sqrshrn2,
	sqrshrun,
	sqrshrun2,
	sqshlu,
	sqshl,
	sqshrn,
	sqshrn2,
	sqshrun,
	sqshrun2,
	sqsub,
	sqxtn2,
	sqxtn,
	sqxtun2,
	sqxtun,
	srhadd,
	sri,
	srshl,
	srshr,
	srsra,
	sshll2,
	sshll,
	sshl,
	sshr,
	ssra,
	ssubl2,
	ssubl,
	ssubw2,
	ssubw,
	st1,
	st2,
	st3,
	st4,
	stlrb,
	stlrh,
	stlr,
	stlxp,
	stlxrb,
	stlxrh,
	stlxr,
	stnp,
	stp,
	strb,
	str,
	strh,
	sttrb,
	sttrh,
	sttr,
	sturb,
	stur,
	sturh,
	stxp,
	stxrb,
	stxrh,
	stxr,
	subhn,
	subhn2,
	sub,
	suqadd,
	svc,
	sysl,
	sys,
	tbl,
	tbnz,
	tbx,
	tbz,
	trn1,
	trn2,
	uabal2,
	uabal,
	uaba,
	uabdl2,
	uabdl,
	uabd,
	uadalp,
	uaddlp,
	uaddlv,
	uaddl2,
	uaddl,
	uaddw2,
	uaddw,
	ubfm,
	ucvtf,
	udiv,
	uhadd,
	uhsub,
	umaddl,
	umaxp,
	umaxv,
	umax,
	uminp,
	uminv,
	umin,
	umlal2,
	umlal,
	umlsl2,
	umlsl,
	umov,
	umsubl,
	umulh,
	umull2,
	umull,
	uqadd,
	uqrshl,
	uqrshrn,
	uqrshrn2,
	uqshl,
	uqshrn,
	uqshrn2,
	uqsub,
	uqxtn2,
	uqxtn,
	urecpe,
	urhadd,
	urshl,
	urshr,
	ursqrte,
	ursra,
	ushll2,
	ushll,
	ushl,
	ushr,
	usqadd,
	usra,
	usubl2,
	usubl,
	usubw2,
	usubw,
	uzp1,
	uzp2,
	xtn2,
	xtn,
	zip1,
	zip2,

	// Alias instructions
	mneg,
	umnegl,
	smnegl,
	nop,
	yield,
	wfe,
	wfi,
	sev,
	sevl,
	ngc,
	sbfiz,
	ubfiz,
	sbfx,
	ubfx,
	bfi,
	bfxil,
	cmn,
	mvn,
	tst,
	cset,
	cinc,
	csetm,
	cinv,
	cneg,
	sxtb,
	sxth,
	sxtw,
	cmp,
	uxtb,
	uxth,
	uxtw,
	ic,
	dc,
	at,
	tlbi
}

/// Group of ARM64 instructions
enum Arm64InstructionGroup {
	invalid = 0,

	// Generic groups
	// All jump instructions (conditional+direct+indirect jumps)
	jump,

	// Architecture-specific groups
	crypto = 128,
	fparmv8,
	neon,
	crc
}