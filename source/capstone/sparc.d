/// Types and constants of SPARC architecturem
module capstone.sparc;

import std.variant;
import std.exception: enforce;
import std.conv: to;
import std.typecons: BitFlags;

import capstone.internal;
import capstone.utils;

/** Instruction's operand referring to memory

This is associated with the `SparcOpType.mem` operand type
*/
struct SparcOpMem {
	SparcRegister base;	 /// Base register
	SparcRegister index; /// Index register
	int disp;    		 /// Displacement/offset value

	this(sparc_op_mem internal){
		base = internal.base.to!SparcRegister;
		index = internal.index.to!SparcRegister;
		disp = internal.disp;
	}
}

/// Tagged union of possible operand types
alias SparcOpValue = TaggedUnion!(SparcRegister, "reg", int, "imm", SparcOpMem, "mem");

/// Instruction's operand
struct SparcOp {
    SparcOpType type;   /// Operand type
    SparcOpValue value; /// Operand value of type `type`
    alias value this; 	/// Convenient access to value (as in original bindings)

    package this(cs_sparc_op internal){
        type = internal.type;
        final switch(internal.type) {
            case SparcOpType.invalid:
                break;
            case SparcOpType.reg:
                value.reg = internal.reg;
                break;
            case SparcOpType.imm:
                value.imm = internal.imm;
                break;
            case SparcOpType.mem:
                value.mem = SparcOpMem(internal.mem);
                break;
        }
    }
}

/// Sparc-specific information about an instruction
struct SparcInstructionDetail {
	SparcCc cc; 			 /// Code condition for this instruction
	BitFlags!SparcHint hint; /// Branch hint: encoding as bitwise OR of `SparcHint`, invalid if = 0
    SparcOp[] operands; 	 /// Operands for this instruction.

    package this(cs_arch_detail arch_detail){
		this(arch_detail.sparc);
	}
    package this(cs_sparc internal){
		cc = internal.cc;
		hint = internal.hint;
        foreach(op; internal.operands[0..internal.op_count])
            operands ~= SparcOp(op);
    }
}

//=============================================================================
// Constants
//=============================================================================

/// Operand type for instruction's operands
enum SparcOpType {
	invalid = 0, /// Uninitialized
	reg, 		 /// Register operand
	imm, 		 /// Immediate operand
	mem, 		 /// Memory operand
}

/// Enums corresponding to Sparc condition codes, both icc's and fcc's.
enum SparcCc {
	invalid = 0,	   /// Invalid CC (default)

	// Integer condition codes
	icc_a   =  8+256,  /// Always
	icc_n   =  0+256,  /// Never
	icc_ne  =  9+256,  /// Not Equal
	icc_e   =  1+256,  /// Equal
	icc_g   = 10+256,  /// Greater
	icc_le  =  2+256,  /// Less or Equal
	icc_ge  = 11+256,  /// Greater or Equal
	icc_l   =  3+256,  /// Less
	icc_gu  = 12+256,  /// Greater Unsigned
	icc_leu =  4+256,  /// Less or Equal Unsigned
	icc_cc  = 13+256,  /// Carry Clear/Great or Equal Unsigned
	icc_cs  =  5+256,  /// Carry Set/Less Unsigned
	icc_pos = 14+256,  /// Positive
	icc_neg =  6+256,  /// Negative
	icc_vc  = 15+256,  /// Overflow Clear
	icc_vs  =  7+256,  /// Overflow Set

	// Floating condition codes
	fcc_a   =  8+16+256,  /// Always
	fcc_n   =  0+16+256,  /// Never
	fcc_u   =  7+16+256,  /// Unordered
	fcc_g   =  6+16+256,  /// Greater
	fcc_ug  =  5+16+256,  /// Unordered or Greater
	fcc_l   =  4+16+256,  /// Less
	fcc_ul  =  3+16+256,  /// Unordered or Less
	fcc_lg  =  2+16+256,  /// Less or Greater
	fcc_ne  =  1+16+256,  /// Not Equal
	fcc_e   =  9+16+256,  /// Equal
	fcc_ue  = 10+16+256,  /// Unordered or Equal
	fcc_ge  = 11+16+256,  /// Greater or Equal
	fcc_uge = 12+16+256,  /// Unordered or Greater or Equal
	fcc_le  = 13+16+256,  /// Less or Equal
	fcc_ule = 14+16+256,  /// Unordered or Less or Equal
	fcc_o   = 15+16+256,  /// Ordered
}

/// Branch hint
enum SparcHint {
	invalid = 0,	/// No hint
	a	= 1 << 0,	/// Annul delay slot instruction
	pt	= 1 << 1,	/// Branch taken
	pn	= 1 << 2,	/// Branch NOT taken
}

/// SPARC registers
enum SparcRegister {
	invalid = 0,

	f0,
	f1,
	f2,
	f3,
	f4,
	f5,
	f6,
	f7,
	f8,
	f9,
	f10,
	f11,
	f12,
	f13,
	f14,
	f15,
	f16,
	f17,
	f18,
	f19,
	f20,
	f21,
	f22,
	f23,
	f24,
	f25,
	f26,
	f27,
	f28,
	f29,
	f30,
	f31,
	f32,
	f34,
	f36,
	f38,
	f40,
	f42,
	f44,
	f46,
	f48,
	f50,
	f52,
	f54,
	f56,
	f58,
	f60,
	f62,
	fcc0,	// Floating condition codes
	fcc1,
	fcc2,
	fcc3,
	fp,
	g0,
	g1,
	g2,
	g3,
	g4,
	g5,
	g6,
	g7,
	i0,
	i1,
	i2,
	i3,
	i4,
	i5,
	i7,
	icc,	// Integer condition codes
	l0,
	l1,
	l2,
	l3,
	l4,
	l5,
	l6,
	l7,
	o0,
	o1,
	o2,
	o3,
	o4,
	o5,
	o7,
	sp,
	y,

	// Special register
	xcc,

	// Extras
	o6 = sp,
	i6 = fp,
}

/// SPARC instruction
enum SparcInstructionId {
	invalid = 0,

	addcc,
	addx,
	addxcc,
	addxc,
	addxccc,
	add,
	alignaddr,
	alignaddrl,
	andcc,
	andncc,
	andn,
	and,
	array16,
	array32,
	array8,
	b,
	jmp,
	bmask,
	fb,
	brgez,
	brgz,
	brlez,
	brlz,
	brnz,
	brz,
	bshuffle,
	call,
	casx,
	cas,
	cmask16,
	cmask32,
	cmask8,
	cmp,
	edge16,
	edge16l,
	edge16ln,
	edge16n,
	edge32,
	edge32l,
	edge32ln,
	edge32n,
	edge8,
	edge8l,
	edge8ln,
	edge8n,
	fabsd,
	fabsq,
	fabss,
	faddd,
	faddq,
	fadds,
	faligndata,
	fand,
	fandnot1,
	fandnot1s,
	fandnot2,
	fandnot2s,
	fands,
	fchksm16,
	fcmpd,
	fcmpeq16,
	fcmpeq32,
	fcmpgt16,
	fcmpgt32,
	fcmple16,
	fcmple32,
	fcmpne16,
	fcmpne32,
	fcmpq,
	fcmps,
	fdivd,
	fdivq,
	fdivs,
	fdmulq,
	fdtoi,
	fdtoq,
	fdtos,
	fdtox,
	fexpand,
	fhaddd,
	fhadds,
	fhsubd,
	fhsubs,
	fitod,
	fitoq,
	fitos,
	flcmpd,
	flcmps,
	flushw,
	fmean16,
	fmovd,
	fmovq,
	fmovrdgez,
	fmovrqgez,
	fmovrsgez,
	fmovrdgz,
	fmovrqgz,
	fmovrsgz,
	fmovrdlez,
	fmovrqlez,
	fmovrslez,
	fmovrdlz,
	fmovrqlz,
	fmovrslz,
	fmovrdnz,
	fmovrqnz,
	fmovrsnz,
	fmovrdz,
	fmovrqz,
	fmovrsz,
	fmovs,
	fmul8sux16,
	fmul8ulx16,
	fmul8x16,
	fmul8x16al,
	fmul8x16au,
	fmuld,
	fmuld8sux16,
	fmuld8ulx16,
	fmulq,
	fmuls,
	fnaddd,
	fnadds,
	fnand,
	fnands,
	fnegd,
	fnegq,
	fnegs,
	fnhaddd,
	fnhadds,
	fnor,
	fnors,
	fnot1,
	fnot1s,
	fnot2,
	fnot2s,
	fone,
	fones,
	for_,
	fornot1,
	fornot1s,
	fornot2,
	fornot2s,
	fors,
	fpack16,
	fpack32,
	fpackfix,
	fpadd16,
	fpadd16s,
	fpadd32,
	fpadd32s,
	fpadd64,
	fpmerge,
	fpsub16,
	fpsub16s,
	fpsub32,
	fpsub32s,
	fqtod,
	fqtoi,
	fqtos,
	fqtox,
	fslas16,
	fslas32,
	fsll16,
	fsll32,
	fsmuld,
	fsqrtd,
	fsqrtq,
	fsqrts,
	fsra16,
	fsra32,
	fsrc1,
	fsrc1s,
	fsrc2,
	fsrc2s,
	fsrl16,
	fsrl32,
	fstod,
	fstoi,
	fstoq,
	fstox,
	fsubd,
	fsubq,
	fsubs,
	fxnor,
	fxnors,
	fxor,
	fxors,
	fxtod,
	fxtoq,
	fxtos,
	fzero,
	fzeros,
	jmpl,
	ldd,
	ld,
	ldq,
	ldsb,
	ldsh,
	ldsw,
	ldub,
	lduh,
	ldx,
	lzcnt,
	membar,
	movdtox,
	mov,
	movrgez,
	movrgz,
	movrlez,
	movrlz,
	movrnz,
	movrz,
	movstosw,
	movstouw,
	mulx,
	nop,
	orcc,
	orncc,
	orn,
	or,
	pdist,
	pdistn,
	popc,
	rd,
	restore,
	rett,
	save,
	sdivcc,
	sdivx,
	sdiv,
	sethi,
	shutdown,
	siam,
	sllx,
	sll,
	smulcc,
	smul,
	srax,
	sra,
	srlx,
	srl,
	stbar,
	stb,
	std,
	st,
	sth,
	stq,
	stx,
	subcc,
	subx,
	subxcc,
	sub,
	swap,
	taddcctv,
	taddcc,
	t,
	tsubcctv,
	tsubcc,
	udivcc,
	udivx,
	udiv,
	umulcc,
	umulxhi,
	umul,
	unimp,
	fcmped,
	fcmpeq,
	fcmpes,
	wr,
	xmulx,
	xmulxhi,
	xnorcc,
	xnor,
	xorcc,
	xor,

	// alias instructions
	ret,
	retl,
}

/// Group of SPARC instructions
enum SparcInstructionGroup {
	invalid = 0,

	// Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	jump,

	// Architecture-specific groups
	hardquad = 128,
	v9,
	vis,
	vis2,
	vis3, 
	bit32,
	bit64,
}