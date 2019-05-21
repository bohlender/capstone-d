/// Types and constants of X86 architecture
module capstone.x86;

import std.conv: to;
import std.typecons: BitFlags;

import capstone.api;
import capstone.capstone;
import capstone.detail;
import capstone.instruction;
import capstone.instructiongroup;
import capstone.internal;
import capstone.register;
import capstone.utils;

/// Architecture-specific Register variant
class X86Register : RegisterImpl!X86RegisterId {
    this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class X86InstructionGroup : InstructionGroupImpl!X86InstructionGroupId {
    this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class X86Detail : DetailImpl!(X86Register, X86InstructionGroup, X86InstructionDetail) {
    this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class X86Instruction : InstructionImpl!(X86InstructionId, X86Register, X86Detail) {
    this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneX86 : CapstoneImpl!(X86InstructionId, X86Instruction) {
    this(in ModeFlags modeFlags){
        super(Arch.x86, modeFlags);
    }
}

struct X86Encoding {
	/// ModR/M offset, or 0 when irrelevant
	ubyte modrmOffset;

	/// Displacement offset, or 0 when irrelevant.
	ubyte dispOffset;
	ubyte dispSize;

	/// Immediate offset, or 0 when irrelevant.
	ubyte immOffset;
	ubyte immSize;

	this(cs_x86_encoding internal){
		modrmOffset = internal.modrm_offset;
		dispOffset = internal.disp_offset;
		dispSize = internal.disp_size;
		immOffset = internal.imm_offset;
		immSize = internal.imm_size;
	}
}

/** Instruction's operand referring to memory

This is associated with the `X86OpType.mem` operand type
*/
struct X86OpMem {
    X86Register segment; /// Segment register (or `X86Register.invalid` if irrelevant)
    X86Register base;    /// Base register (or `X86Register.invalid` if irrelevant)
    X86Register index;   /// Index register (or `X86Register.invalid` if irrelevant)
    int scale;           /// Scale for index register
    long disp;           /// Displacement value

	this(in Capstone cs, x86_op_mem internal){
		segment = new X86Register(cs, internal.segment);
		base = new X86Register(cs, internal.base);
		index = new X86Register(cs, internal.index);
		scale = internal.scale;
		disp = internal.disp;
	}
}

/// Union of possible operand types
union X86OpValue {
	X86Register reg; /// Register value for REG operand
	long imm;		 /// Immediate value for IMM operand
	X86OpMem mem;	 /// Base/index/scale/disp value for MEM operand
}

/// Instruction's operand
struct X86Op {
    X86OpType type;   /// Operand type
    SafeUnion!X86OpValue value; /// Operand value of type `type`
    alias value this; /// Convenient access to value (as in original bindings)

    ubyte size; /// Size of this operand (in bytes)
	
	/** How is this operand accessed? (READ, WRITE or READ|WRITE)

	NOTE: This field is irrelevant, i.e. equals 0, if engine is compiled in DIET mode.
    */
	AccessFlags access;

    X86AvxBroadcast avxBcast; /// AVX broadcast type, or `X86AvxBroadcast.invalid`
    bool avxZeroOpmask;       /// AVX zero opmask {z}

    package this(in Capstone cs, cs_x86_op internal){
        type = internal.type.to!X86OpType;
        final switch(internal.type) {
            case X86OpType.invalid:
                break;
            case X86OpType.reg:
                value.reg = new X86Register(cs, internal.reg);
                break;
            case X86OpType.imm:
                value.imm = internal.imm;
                break;
            case X86OpType.mem:
                value.mem = X86OpMem(cs, internal.mem);
                break;
        }
        size = internal.size;
        access = cast(AccessType)internal.access;
        avxBcast = internal.avx_bcast.to!X86AvxBroadcast;
        avxZeroOpmask = internal.avx_zero_opmask;
    }
}

/// X86-specific information about an instruction
struct X86InstructionDetail {
    /** Instruction prefix, which can be up to 4 bytes.

    A prefix byte gets value 0 when irrelevant.
    $(OL
        $(LI `prefix[0]` indicates REP/REPNE/LOCK prefix (See `X86Prefix.rep`, `X86Prefix.repne`, `X86Prefix.lock`))
        $(LI `prefix[1]` indicates segment override (irrelevant for x86_64):
                See `X86Prefix.cs`,`X86Prefix.ss`,`X86Prefix.ds`,`X86Prefix.es`,`X86Prefix.fs`,`X86Prefix.gs`)
        $(LI `prefix[2]` indicates operand-size override (`X86Prefix.opsize`))
        $(LI `prefix[3]` indicates address-size override (`X86Prefix.addrsize`))
    )
    */
    ubyte[] prefix; // TODO: Split? Get rid of trailing 0 bytes?

    /** Instruction opcode, wich can be from 1 to 4 bytes in size.

    This contains VEX opcode as well. A trailing opcode byte gets value 0 when irrelevant.
    */
    ubyte[] opcode; // TODO: Get rid of irrelevant trailing bytes?
    ubyte rex;      /// REX prefix: only a non-zero value is relavant for x86_64
    ubyte addrSize; /// Address size
    ubyte modRM;    /// ModR/M byte
    ubyte sib;      /// SIB value, or 0 when irrelevant
    long disp;      /// Displacement value, or 0 when irrelevant

    // SIB state
    X86Register sibIndex;      /// SIB index register, or `X86Register.invalid` when irrelevant
    byte sibScale;             /// SIB scale. Only applicable if `sibIndex` is relavant
    X86Register sibBase;       /// SIB base register, or `X86Register.invalid` when irrelevant

	X86XopCc xopCc;			   /// XOP Code Condition
    X86SseCodeCondition sseCc; /// SSE code condition
    X86AvxCodeCondition avxCc; /// AVX code condition
    bool avxSae;               /// AVX suppress all exceptions
    X86AvxRoundingMode avxRM;  /// AVX static rounding mode

	union{
		EFlags eflags;		   /// EFLAGS updated by this instruction
		FpuFlags fpuFlags;	   /// FPUFLAGS updated by this instruction
	}

    X86Op[] operands;          /// Operands for this instruction.
	X86Encoding encoding;	   /// Encoding information

    package this(in Capstone cs, cs_arch_detail arch_detail){
        auto internal = arch_detail.x86;
        prefix = internal.prefix.dup;
        opcode = internal.opcode.dup;
        rex = internal.rex;
        addrSize = internal.addr_size;
        modRM = internal.modrm;
        sib = internal.sib;
        disp = internal.disp;
        sibIndex = new X86Register(cs, internal.sib_index);
        sibScale = internal.sib_scale;
        sibBase = new X86Register(cs, internal.sib_base);
		xopCc = internal.xop_cc.to!X86XopCc;
        sseCc = internal.sse_cc.to!X86SseCodeCondition;
        avxCc = internal.avx_cc.to!X86AvxCodeCondition;
		eflags = cast(EFlag)internal.eflags; // covers fpuFlags too
        avxRM = internal.avx_rm.to!X86AvxRoundingMode;
		encoding = internal.encoding.to!X86Encoding;

        foreach(op; internal.operands[0..internal.op_count])
            operands ~= X86Op(cs, op);
    }
}

/// Operand type for instruction's operands
enum X86OpType {
    invalid = 0, /// Invalid
    reg,         /// Register operand (`X86Register`)
    imm,         /// Immediate operand (`long`)
    mem,         /// Memory operand (`X86OpMem`)
}

/// XOP Code Condition type
enum X86XopCc {
	invalid = 0,
	lt,
	le,
	gt,
	ge,
	eq,
	neq,
	false_,
	true_,
}

/// AVX broadcast type
enum X86AvxBroadcast {
    invalid = 0, /// Invalid
    bcast_2,     /// avx512 broadcast type {1to2}
    bcast_4,     /// avx512 broadcast type {1to4}
    bcast_8,     /// avx512 broadcast type {1to8}
    bcast_16     /// avx512 broadcast type {1to16}
}

/// SSE code condition type
enum X86SseCodeCondition {
    invalid = 0,
    eq,
    lt,
    le,
    unord,
    neq,
    nlt,
    nle,
    ord,
    eq_uq,
    nge,
    ngt,
    false_,
    neq_oq,
    ge,
    gt,
    true_
}

/// AVX code condition type
enum X86AvxCodeCondition {
    invalid = 0,
    eq,
    lt,
    le,
    unord,
    neq,
    nlt,
    nle,
    ord,
    eq_uq,
    nge,
    ngt,
    false_,
    neq_oq,
    ge,
    gt,
    true_,
    eq_os,
    lt_oq,
    le_oq,
    unord_s,
    neq_us,
    nlt_uq,
    nle_uq,
    ord_s,
    eq_us,
    nge_uq,
    ngt_uq,
    false_os,
    neq_os,
    ge_oq,
    gt_oq,
    true_us
}

/// AVX static rounding mode type
enum X86AvxRoundingMode {
    invalid = 0, /// Invalid
    rn,          /// Round to nearest
    rd,          /// Round down
    ru,          /// Round up
    rz           /// Round toward zero
}

/// Instruction prefixes - used in `X86InstructionDetail.prefix[]`
enum X86Prefix {
    lock        =   0xf0,   // lock (cs_x86.prefix[0]
    rep         =   0xf3,   // rep (cs_x86.prefix[0]
    repne       =   0xf2,   // repne (cs_x86.prefix[0]

    cs          =   0x2e,   // segment override cs (cs_x86.prefix[1]
    ss          =   0x36,   // segment override ss (cs_x86.prefix[1]
    ds          =   0x3e,   // segment override ds (cs_x86.prefix[1]
    es          =   0x26,   // segment override es (cs_x86.prefix[1]
    fs          =   0x64,   // segment override fs (cs_x86.prefix[1]
    gs          =   0x65,   // segment override gs (cs_x86.prefix[1]

    opsize      =   0x66,   // operand-size override (cs_x86.prefix[2]
    addrsize    =   0x67    // address-size override (cs_x86.prefix[3]
}

enum EFlag : ulong {
	mod_af = 1UL << 0,
	mod_cf = 1UL << 1,
	mod_sf = 1UL << 2,
	mod_zf = 1UL << 3,
	mod_pf = 1UL << 4,
	mod_of = 1UL << 5,
	mod_tf = 1UL << 6,
	mod_if = 1UL << 7,
	mod_df = 1UL << 8,
	mod_nt = 1UL << 9,
	mod_rf = 1UL << 10,
	prior_of = 1UL << 11,
	prior_sf = 1UL << 12,
	prior_zf = 1UL << 13,
	prior_af = 1UL << 14,
	prior_pf = 1UL << 15,
	prior_cf = 1UL << 16,
	prior_tf = 1UL << 17,
	prior_if = 1UL << 18,
	prior_df = 1UL << 19,
	prior_nt = 1UL << 20,
	reset_of = 1UL << 21,
	reset_cf = 1UL << 22,
	reset_df = 1UL << 23,
	reset_if = 1UL << 24,
	reset_sf = 1UL << 25,
	reset_af = 1UL << 26,
	reset_tf = 1UL << 27,
	reset_nt = 1UL << 28,
	reset_pf = 1UL << 29,
	set_cf = 1UL << 30,
	set_df = 1UL << 31,
	set_if = 1UL << 32,
	test_of = 1UL << 33,
	test_sf = 1UL << 34,
	test_zf = 1UL << 35,
	test_pf = 1UL << 36,
	test_cf = 1UL << 37,
	test_nt = 1UL << 38,
	test_df = 1UL << 39,
	undef_of = 1UL << 40,
	undef_sf = 1UL << 41,
	undef_zf = 1UL << 42,
	undef_pf = 1UL << 43,
	undef_af = 1UL << 44,
	undef_cf = 1UL << 45,
	reset_rf  = 1UL << 46,
	test_rf = 1UL << 47,
	test_if = 1UL << 48,
	test_tf = 1UL << 49,
	test_af = 1UL << 50,
	reset_zf = 1UL << 51,
	set_of = 1UL << 52,
	set_sf = 1UL << 53,
	set_zf = 1UL << 54,
	set_af = 1UL << 55,
	set_pf = 1UL << 56,
	reset_0f = 1UL << 57,
	reset_ac = 1UL << 58
}
alias EFlags = BitFlags!EFlag;

enum FpuFlag : ulong {
	mod_c0 = 1UL << 0,
	mod_c1 = 1UL << 1,
	mod_c2 = 1UL << 2,
	mod_c3 = 1UL << 3,
	reset_c0 = 1UL << 4,
	reset_c1 = 1UL << 5,
	reset_c2 = 1UL << 6,
	reset_c3 = 1UL << 7,
	set_c0 = 1UL << 8,
	set_c1 = 1UL << 9,
	set_c2 = 1UL << 10,
	set_c3 = 1UL << 11,
	undef_c0 = 1UL << 12,
	undef_c1 = 1UL << 13,
	undef_c2 = 1UL << 14,
	undef_c3 = 1UL << 15,
	test_c0 = 1UL << 16,
	test_c1 = 1UL << 17,
	test_c2 = 1UL << 18,
	test_c3 = 1UL << 19,
}
alias FpuFlags = BitFlags!FpuFlag;

/// X86 registers
enum X86RegisterId {
    invalid = 0,
	ah, al, ax, bh, bl,
	bp, bpl, bx, ch, cl,
	cs, cx, dh, di, dil,
	dl, ds, dx, eax, ebp,
	ebx, ecx, edi, edx, eflags,
	eip, eiz, es, esi, esp,
	fpsw, fs, gs, ip, rax,
	rbp, rbx, rcx, rdi, rdx,
	rip, riz, rsi, rsp, si,
	sil, sp, spl, ss, cr0,
	cr1, cr2, cr3, cr4, cr5,
	cr6, cr7, cr8, cr9, cr10,
	cr11, cr12, cr13, cr14, cr15,
	dr0, dr1, dr2, dr3, dr4,
	dr5, dr6, dr7, dr8, dr9,
	dr10, dr11, dr12, dr13, dr14,
	dr15, fp0, fp1, fp2, fp3,
	fp4, fp5, fp6, fp7,
	k0, k1, k2, k3, k4,
	k5, k6, k7, mm0, mm1,
	mm2, mm3, mm4, mm5, mm6,
	mm7, r8, r9, r10, r11,
	r12, r13, r14, r15,
	st0, st1, st2, st3,
	st4, st5, st6, st7,
	xmm0, xmm1, xmm2, xmm3, xmm4,
	xmm5, xmm6, xmm7, xmm8, xmm9,
	xmm10, xmm11, xmm12, xmm13, xmm14,
	xmm15, xmm16, xmm17, xmm18, xmm19,
	xmm20, xmm21, xmm22, xmm23, xmm24,
	xmm25, xmm26, xmm27, xmm28, xmm29,
	xmm30, xmm31, ymm0, ymm1, ymm2,
	ymm3, ymm4, ymm5, ymm6, ymm7,
	ymm8, ymm9, ymm10, ymm11, ymm12,
	ymm13, ymm14, ymm15, ymm16, ymm17,
	ymm18, ymm19, ymm20, ymm21, ymm22,
	ymm23, ymm24, ymm25, ymm26, ymm27,
	ymm28, ymm29, ymm30, ymm31, zmm0,
	zmm1, zmm2, zmm3, zmm4, zmm5,
	zmm6, zmm7, zmm8, zmm9, zmm10,
	zmm11, zmm12, zmm13, zmm14, zmm15,
	zmm16, zmm17, zmm18, zmm19, zmm20,
	zmm21, zmm22, zmm23, zmm24, zmm25,
	zmm26, zmm27, zmm28, zmm29, zmm30,
	zmm31, r8b, r9b, r10b, r11b,
	r12b, r13b, r14b, r15b, r8d,
	r9d, r10d, r11d, r12d, r13d,
	r14d, r15d, r8w, r9w, r10w,
    r11w, r12w, r13w, r14w, r15w,
}

/// X86 instructions
enum X86InstructionId {
    invalid = 0,

	aaa,
	aad,
	aam,
	aas,
	fabs,
	adc,
	adcx,
	add,
	addpd,
	addps,
	addsd,
	addss,
	addsubpd,
	addsubps,
	fadd,
	fiadd,
	faddp,
	adox,
	aesdeclast,
	aesdec,
	aesenclast,
	aesenc,
	aesimc,
	aeskeygenassist,
	and,
	andn,
	andnpd,
	andnps,
	andpd,
	andps,
	arpl,
	bextr,
	blcfill,
	blci,
	blcic,
	blcmsk,
	blcs,
	blendpd,
	blendps,
	blendvpd,
	blendvps,
	blsfill,
	blsi,
	blsic,
	blsmsk,
	blsr,
	bound,
	bsf,
	bsr,
	bswap,
	bt,
	btc,
	btr,
	bts,
	bzhi,
	call,
	cbw,
	cdq,
	cdqe,
	fchs,
	clac,
	clc,
	cld,
	clflush,
	clflushopt,
	clgi,
	cli,
	clts,
	clwb,
	cmc,
	cmova,
	cmovae,
	cmovb,
	cmovbe,
	fcmovbe,
	fcmovb,
	cmove,
	fcmove,
	cmovg,
	cmovge,
	cmovl,
	cmovle,
	fcmovnbe,
	fcmovnb,
	cmovne,
	fcmovne,
	cmovno,
	cmovnp,
	fcmovnu,
	cmovns,
	cmovo,
	cmovp,
	fcmovu,
	cmovs,
	cmp,
	cmpsb,
	cmpsq,
	cmpsw,
	cmpxchg16b,
	cmpxchg,
	cmpxchg8b,
	comisd,
	comiss,
	fcomp,
	fcomip,
	fcomi,
	fcom,
	fcos,
	cpuid,
	cqo,
	crc32,
	cvtdq2pd,
	cvtdq2ps,
	cvtpd2dq,
	cvtpd2ps,
	cvtps2dq,
	cvtps2pd,
	cvtsd2si,
	cvtsd2ss,
	cvtsi2sd,
	cvtsi2ss,
	cvtss2sd,
	cvtss2si,
	cvttpd2dq,
	cvttps2dq,
	cvttsd2si,
	cvttss2si,
	cwd,
	cwde,
	daa,
	das,
	data16,
	dec,
	div,
	divpd,
	divps,
	fdivr,
	fidivr,
	fdivrp,
	divsd,
	divss,
	fdiv,
	fidiv,
	fdivp,
	dppd,
	dpps,
	ret,
	encls,
	enclu,
	enter,
	extractps,
	extrq,
	f2xm1,
	lcall,
	ljmp,
	fbld,
	fbstp,
	fcompp,
	fdecstp,
	femms,
	ffree,
	ficom,
	ficomp,
	fincstp,
	fldcw,
	fldenv,
	fldl2e,
	fldl2t,
	fldlg2,
	fldln2,
	fldpi,
	fnclex,
	fninit,
	fnop,
	fnstcw,
	fnstsw,
	fpatan,
	fprem,
	fprem1,
	fptan,
	ffreep,
	frndint,
	frstor,
	fnsave,
	fscale,
	fsetpm,
	fsincos,
	fnstenv,
	fxam,
	fxrstor,
	fxrstor64,
	fxsave,
	fxsave64,
	fxtract,
	fyl2x,
	fyl2xp1,
	movapd,
	movaps,
	orpd,
	orps,
	vmovapd,
	vmovaps,
	xorpd,
	xorps,
	getsec,
	haddpd,
	haddps,
	hlt,
	hsubpd,
	hsubps,
	idiv,
	fild,
	imul,
	in_,
	inc,
	insb,
	insertps,
	insertq,
	insd,
	insw,
	int_,
	int1,
	int3,
	into,
	invd,
	invept,
	invlpg,
	invlpga,
	invpcid,
	invvpid,
	iret,
	iretd,
	iretq,
	fisttp,
	fist,
	fistp,
	ucomisd,
	ucomiss,
	vcomisd,
	vcomiss,
	vcvtsd2ss,
	vcvtsi2sd,
	vcvtsi2ss,
	vcvtss2sd,
	vcvttsd2si,
	vcvttsd2usi,
	vcvttss2si,
	vcvttss2usi,
	vcvtusi2sd,
	vcvtusi2ss,
	vucomisd,
	vucomiss,
	jae,
	ja,
	jbe,
	jb,
	jcxz,
	jecxz,
	je,
	jge,
	jg,
	jle,
	jl,
	jmp,
	jne,
	jno,
	jnp,
	jns,
	jo,
	jp,
	jrcxz,
	js,
	kandb,
	kandd,
	kandnb,
	kandnd,
	kandnq,
	kandnw,
	kandq,
	kandw,
	kmovb,
	kmovd,
	kmovq,
	kmovw,
	knotb,
	knotd,
	knotq,
	knotw,
	korb,
	kord,
	korq,
	kortestb,
	kortestd,
	kortestq,
	kortestw,
	korw,
	kshiftlb,
	kshiftld,
	kshiftlq,
	kshiftlw,
	kshiftrb,
	kshiftrd,
	kshiftrq,
	kshiftrw,
	kunpckbw,
	kxnorb,
	kxnord,
	kxnorq,
	kxnorw,
	kxorb,
	kxord,
	kxorq,
	kxorw,
	lahf,
	lar,
	lddqu,
	ldmxcsr,
	lds,
	fldz,
	fld1,
	fld,
	lea,
	leave,
	les,
	lfence,
	lfs,
	lgdt,
	lgs,
	lidt,
	lldt,
	lmsw,
	or,
	sub,
	xor,
	lodsb,
	lodsd,
	lodsq,
	lodsw,
	loop,
	loope,
	loopne,
	retf,
	retfq,
	lsl,
	lss,
	ltr,
	xadd,
	lzcnt,
	maskmovdqu,
	maxpd,
	maxps,
	maxsd,
	maxss,
	mfence,
	minpd,
	minps,
	minsd,
	minss,
	cvtpd2pi,
	cvtpi2pd,
	cvtpi2ps,
	cvtps2pi,
	cvttpd2pi,
	cvttps2pi,
	emms,
	maskmovq,
	movd,
	movdq2q,
	movntq,
	movq2dq,
	movq,
	pabsb,
	pabsd,
	pabsw,
	packssdw,
	packsswb,
	packuswb,
	paddb,
	paddd,
	paddq,
	paddsb,
	paddsw,
	paddusb,
	paddusw,
	paddw,
	palignr,
	pandn,
	pand,
	pavgb,
	pavgw,
	pcmpeqb,
	pcmpeqd,
	pcmpeqw,
	pcmpgtb,
	pcmpgtd,
	pcmpgtw,
	pextrw,
	phaddsw,
	phaddw,
	phaddd,
	phsubd,
	phsubsw,
	phsubw,
	pinsrw,
	pmaddubsw,
	pmaddwd,
	pmaxsw,
	pmaxub,
	pminsw,
	pminub,
	pmovmskb,
	pmulhrsw,
	pmulhuw,
	pmulhw,
	pmullw,
	pmuludq,
	por,
	psadbw,
	pshufb,
	pshufw,
	psignb,
	psignd,
	psignw,
	pslld,
	psllq,
	psllw,
	psrad,
	psraw,
	psrld,
	psrlq,
	psrlw,
	psubb,
	psubd,
	psubq,
	psubsb,
	psubsw,
	psubusb,
	psubusw,
	psubw,
	punpckhbw,
	punpckhdq,
	punpckhwd,
	punpcklbw,
	punpckldq,
	punpcklwd,
	pxor,
	monitor,
	montmul,
	mov,
	movabs,
	movbe,
	movddup,
	movdqa,
	movdqu,
	movhlps,
	movhpd,
	movhps,
	movlhps,
	movlpd,
	movlps,
	movmskpd,
	movmskps,
	movntdqa,
	movntdq,
	movnti,
	movntpd,
	movntps,
	movntsd,
	movntss,
	movsb,
	movsd,
	movshdup,
	movsldup,
	movsq,
	movss,
	movsw,
	movsx,
	movsxd,
	movupd,
	movups,
	movzx,
	mpsadbw,
	mul,
	mulpd,
	mulps,
	mulsd,
	mulss,
	mulx,
	fmul,
	fimul,
	fmulp,
	mwait,
	neg,
	nop,
	not,
	out_,
	outsb,
	outsd,
	outsw,
	packusdw,
	pause,
	pavgusb,
	pblendvb,
	pblendw,
	pclmulqdq,
	pcmpeqq,
	pcmpestri,
	pcmpestrm,
	pcmpgtq,
	pcmpistri,
	pcmpistrm,
	pcommit,
	pdep,
	pext,
	pextrb,
	pextrd,
	pextrq,
	pf2id,
	pf2iw,
	pfacc,
	pfadd,
	pfcmpeq,
	pfcmpge,
	pfcmpgt,
	pfmax,
	pfmin,
	pfmul,
	pfnacc,
	pfpnacc,
	pfrcpit1,
	pfrcpit2,
	pfrcp,
	pfrsqit1,
	pfrsqrt,
	pfsubr,
	pfsub,
	phminposuw,
	pi2fd,
	pi2fw,
	pinsrb,
	pinsrd,
	pinsrq,
	pmaxsb,
	pmaxsd,
	pmaxud,
	pmaxuw,
	pminsb,
	pminsd,
	pminud,
	pminuw,
	pmovsxbd,
	pmovsxbq,
	pmovsxbw,
	pmovsxdq,
	pmovsxwd,
	pmovsxwq,
	pmovzxbd,
	pmovzxbq,
	pmovzxbw,
	pmovzxdq,
	pmovzxwd,
	pmovzxwq,
	pmuldq,
	pmulhrw,
	pmulld,
	pop,
	popaw,
	popal,
	popcnt,
	popf,
	popfd,
	popfq,
	prefetch,
	prefetchnta,
	prefetcht0,
	prefetcht1,
	prefetcht2,
	prefetchw,
	pshufd,
	pshufhw,
	pshuflw,
	pslldq,
	psrldq,
	pswapd,
	ptest,
	punpckhqdq,
	punpcklqdq,
	push,
	pushaw,
	pushal,
	pushf,
	pushfd,
	pushfq,
	rcl,
	rcpps,
	rcpss,
	rcr,
	rdfsbase,
	rdgsbase,
	rdmsr,
	rdpmc,
	rdrand,
	rdseed,
	rdtsc,
	rdtscp,
	rol,
	ror,
	rorx,
	roundpd,
	roundps,
	roundsd,
	roundss,
	rsm,
	rsqrtps,
	rsqrtss,
	sahf,
	sal,
	salc,
	sar,
	sarx,
	sbb,
	scasb,
	scasd,
	scasq,
	scasw,
	setae,
	seta,
	setbe,
	setb,
	sete,
	setge,
	setg,
	setle,
	setl,
	setne,
	setno,
	setnp,
	setns,
	seto,
	setp,
	sets,
	sfence,
	sgdt,
	sha1msg1,
	sha1msg2,
	sha1nexte,
	sha1rnds4,
	sha256msg1,
	sha256msg2,
	sha256rnds2,
	shl,
	shld,
	shlx,
	shr,
	shrd,
	shrx,
	shufpd,
	shufps,
	sidt,
	fsin,
	skinit,
	sldt,
	smsw,
	sqrtpd,
	sqrtps,
	sqrtsd,
	sqrtss,
	fsqrt,
	stac,
	stc,
	std,
	stgi,
	sti,
	stmxcsr,
	stosb,
	stosd,
	stosq,
	stosw,
	str,
	fst,
	fstp,
	fstpnce,
	fxch,
	subpd,
	subps,
	fsubr,
	fisubr,
	fsubrp,
	subsd,
	subss,
	fsub,
	fisub,
	fsubp,
	swapgs,
	syscall,
	sysenter,
	sysexit,
	sysret,
	t1mskc,
	test,
	ud2,
	ftst,
	tzcnt,
	tzmsk,
	fucomip,
	fucomi,
	fucompp,
	fucomp,
	fucom,
	ud2b,
	unpckhpd,
	unpckhps,
	unpcklpd,
	unpcklps,
	vaddpd,
	vaddps,
	vaddsd,
	vaddss,
	vaddsubpd,
	vaddsubps,
	vaesdeclast,
	vaesdec,
	vaesenclast,
	vaesenc,
	vaesimc,
	vaeskeygenassist,
	valignd,
	valignq,
	vandnpd,
	vandnps,
	vandpd,
	vandps,
	vblendmpd,
	vblendmps,
	vblendpd,
	vblendps,
	vblendvpd,
	vblendvps,
	vbroadcastf128,
	vbroadcasti32x4,
	vbroadcasti64x4,
	vbroadcastsd,
	vbroadcastss,
	vcompresspd,
	vcompressps,
	vcvtdq2pd,
	vcvtdq2ps,
	vcvtpd2dqx,
	vcvtpd2dq,
	vcvtpd2psx,
	vcvtpd2ps,
	vcvtpd2udq,
	vcvtph2ps,
	vcvtps2dq,
	vcvtps2pd,
	vcvtps2ph,
	vcvtps2udq,
	vcvtsd2si,
	vcvtsd2usi,
	vcvtss2si,
	vcvtss2usi,
	vcvttpd2dqx,
	vcvttpd2dq,
	vcvttpd2udq,
	vcvttps2dq,
	vcvttps2udq,
	vcvtudq2pd,
	vcvtudq2ps,
	vdivpd,
	vdivps,
	vdivsd,
	vdivss,
	vdppd,
	vdpps,
	verr,
	verw,
	vexp2pd,
	vexp2ps,
	vexpandpd,
	vexpandps,
	vextractf128,
	vextractf32x4,
	vextractf64x4,
	vextracti128,
	vextracti32x4,
	vextracti64x4,
	vextractps,
	vfmadd132pd,
	vfmadd132ps,
	vfmaddpd,
	vfmadd213pd,
	vfmadd231pd,
	vfmaddps,
	vfmadd213ps,
	vfmadd231ps,
	vfmaddsd,
	vfmadd213sd,
	vfmadd132sd,
	vfmadd231sd,
	vfmaddss,
	vfmadd213ss,
	vfmadd132ss,
	vfmadd231ss,
	vfmaddsub132pd,
	vfmaddsub132ps,
	vfmaddsubpd,
	vfmaddsub213pd,
	vfmaddsub231pd,
	vfmaddsubps,
	vfmaddsub213ps,
	vfmaddsub231ps,
	vfmsub132pd,
	vfmsub132ps,
	vfmsubadd132pd,
	vfmsubadd132ps,
	vfmsubaddpd,
	vfmsubadd213pd,
	vfmsubadd231pd,
	vfmsubaddps,
	vfmsubadd213ps,
	vfmsubadd231ps,
	vfmsubpd,
	vfmsub213pd,
	vfmsub231pd,
	vfmsubps,
	vfmsub213ps,
	vfmsub231ps,
	vfmsubsd,
	vfmsub213sd,
	vfmsub132sd,
	vfmsub231sd,
	vfmsubss,
	vfmsub213ss,
	vfmsub132ss,
	vfmsub231ss,
	vfnmadd132pd,
	vfnmadd132ps,
	vfnmaddpd,
	vfnmadd213pd,
	vfnmadd231pd,
	vfnmaddps,
	vfnmadd213ps,
	vfnmadd231ps,
	vfnmaddsd,
	vfnmadd213sd,
	vfnmadd132sd,
	vfnmadd231sd,
	vfnmaddss,
	vfnmadd213ss,
	vfnmadd132ss,
	vfnmadd231ss,
	vfnmsub132pd,
	vfnmsub132ps,
	vfnmsubpd,
	vfnmsub213pd,
	vfnmsub231pd,
	vfnmsubps,
	vfnmsub213ps,
	vfnmsub231ps,
	vfnmsubsd,
	vfnmsub213sd,
	vfnmsub132sd,
	vfnmsub231sd,
	vfnmsubss,
	vfnmsub213ss,
	vfnmsub132ss,
	vfnmsub231ss,
	vfrczpd,
	vfrczps,
	vfrczsd,
	vfrczss,
	vorpd,
	vorps,
	vxorpd,
	vxorps,
	vgatherdpd,
	vgatherdps,
	vgatherpf0dpd,
	vgatherpf0dps,
	vgatherpf0qpd,
	vgatherpf0qps,
	vgatherpf1dpd,
	vgatherpf1dps,
	vgatherpf1qpd,
	vgatherpf1qps,
	vgatherqpd,
	vgatherqps,
	vhaddpd,
	vhaddps,
	vhsubpd,
	vhsubps,
	vinsertf128,
	vinsertf32x4,
	vinsertf32x8,
	vinsertf64x2,
	vinsertf64x4,
	vinserti128,
	vinserti32x4,
	vinserti32x8,
	vinserti64x2,
	vinserti64x4,
	vinsertps,
	vlddqu,
	vldmxcsr,
	vmaskmovdqu,
	vmaskmovpd,
	vmaskmovps,
	vmaxpd,
	vmaxps,
	vmaxsd,
	vmaxss,
	vmcall,
	vmclear,
	vmfunc,
	vminpd,
	vminps,
	vminsd,
	vminss,
	vmlaunch,
	vmload,
	vmmcall,
	vmovq,
	vmovddup,
	vmovd,
	vmovdqa32,
	vmovdqa64,
	vmovdqa,
	vmovdqu16,
	vmovdqu32,
	vmovdqu64,
	vmovdqu8,
	vmovdqu,
	vmovhlps,
	vmovhpd,
	vmovhps,
	vmovlhps,
	vmovlpd,
	vmovlps,
	vmovmskpd,
	vmovmskps,
	vmovntdqa,
	vmovntdq,
	vmovntpd,
	vmovntps,
	vmovsd,
	vmovshdup,
	vmovsldup,
	vmovss,
	vmovupd,
	vmovups,
	vmpsadbw,
	vmptrld,
	vmptrst,
	vmread,
	vmresume,
	vmrun,
	vmsave,
	vmulpd,
	vmulps,
	vmulsd,
	vmulss,
	vmwrite,
	vmxoff,
	vmxon,
	vpabsb,
	vpabsd,
	vpabsq,
	vpabsw,
	vpackssdw,
	vpacksswb,
	vpackusdw,
	vpackuswb,
	vpaddb,
	vpaddd,
	vpaddq,
	vpaddsb,
	vpaddsw,
	vpaddusb,
	vpaddusw,
	vpaddw,
	vpalignr,
	vpandd,
	vpandnd,
	vpandnq,
	vpandn,
	vpandq,
	vpand,
	vpavgb,
	vpavgw,
	vpblendd,
	vpblendmb,
	vpblendmd,
	vpblendmq,
	vpblendmw,
	vpblendvb,
	vpblendw,
	vpbroadcastb,
	vpbroadcastd,
	vpbroadcastmb2q,
	vpbroadcastmw2d,
	vpbroadcastq,
	vpbroadcastw,
	vpclmulqdq,
	vpcmov,
	vpcmpb,
	vpcmpd,
	vpcmpeqb,
	vpcmpeqd,
	vpcmpeqq,
	vpcmpeqw,
	vpcmpestri,
	vpcmpestrm,
	vpcmpgtb,
	vpcmpgtd,
	vpcmpgtq,
	vpcmpgtw,
	vpcmpistri,
	vpcmpistrm,
	vpcmpq,
	vpcmpub,
	vpcmpud,
	vpcmpuq,
	vpcmpuw,
	vpcmpw,
	vpcomb,
	vpcomd,
	vpcompressd,
	vpcompressq,
	vpcomq,
	vpcomub,
	vpcomud,
	vpcomuq,
	vpcomuw,
	vpcomw,
	vpconflictd,
	vpconflictq,
	vperm2f128,
	vperm2i128,
	vpermd,
	vpermi2d,
	vpermi2pd,
	vpermi2ps,
	vpermi2q,
	vpermil2pd,
	vpermil2ps,
	vpermilpd,
	vpermilps,
	vpermpd,
	vpermps,
	vpermq,
	vpermt2d,
	vpermt2pd,
	vpermt2ps,
	vpermt2q,
	vpexpandd,
	vpexpandq,
	vpextrb,
	vpextrd,
	vpextrq,
	vpextrw,
	vpgatherdd,
	vpgatherdq,
	vpgatherqd,
	vpgatherqq,
	vphaddbd,
	vphaddbq,
	vphaddbw,
	vphadddq,
	vphaddd,
	vphaddsw,
	vphaddubd,
	vphaddubq,
	vphaddubw,
	vphaddudq,
	vphadduwd,
	vphadduwq,
	vphaddwd,
	vphaddwq,
	vphaddw,
	vphminposuw,
	vphsubbw,
	vphsubdq,
	vphsubd,
	vphsubsw,
	vphsubwd,
	vphsubw,
	vpinsrb,
	vpinsrd,
	vpinsrq,
	vpinsrw,
	vplzcntd,
	vplzcntq,
	vpmacsdd,
	vpmacsdqh,
	vpmacsdql,
	vpmacssdd,
	vpmacssdqh,
	vpmacssdql,
	vpmacsswd,
	vpmacssww,
	vpmacswd,
	vpmacsww,
	vpmadcsswd,
	vpmadcswd,
	vpmaddubsw,
	vpmaddwd,
	vpmaskmovd,
	vpmaskmovq,
	vpmaxsb,
	vpmaxsd,
	vpmaxsq,
	vpmaxsw,
	vpmaxub,
	vpmaxud,
	vpmaxuq,
	vpmaxuw,
	vpminsb,
	vpminsd,
	vpminsq,
	vpminsw,
	vpminub,
	vpminud,
	vpminuq,
	vpminuw,
	vpmovdb,
	vpmovdw,
	vpmovm2b,
	vpmovm2d,
	vpmovm2q,
	vpmovm2w,
	vpmovmskb,
	vpmovqb,
	vpmovqd,
	vpmovqw,
	vpmovsdb,
	vpmovsdw,
	vpmovsqb,
	vpmovsqd,
	vpmovsqw,
	vpmovsxbd,
	vpmovsxbq,
	vpmovsxbw,
	vpmovsxdq,
	vpmovsxwd,
	vpmovsxwq,
	vpmovusdb,
	vpmovusdw,
	vpmovusqb,
	vpmovusqd,
	vpmovusqw,
	vpmovzxbd,
	vpmovzxbq,
	vpmovzxbw,
	vpmovzxdq,
	vpmovzxwd,
	vpmovzxwq,
	vpmuldq,
	vpmulhrsw,
	vpmulhuw,
	vpmulhw,
	vpmulld,
	vpmullq,
	vpmullw,
	vpmuludq,
	vpord,
	vporq,
	vpor,
	vpperm,
	vprotb,
	vprotd,
	vprotq,
	vprotw,
	vpsadbw,
	vpscatterdd,
	vpscatterdq,
	vpscatterqd,
	vpscatterqq,
	vpshab,
	vpshad,
	vpshaq,
	vpshaw,
	vpshlb,
	vpshld,
	vpshlq,
	vpshlw,
	vpshufb,
	vpshufd,
	vpshufhw,
	vpshuflw,
	vpsignb,
	vpsignd,
	vpsignw,
	vpslldq,
	vpslld,
	vpsllq,
	vpsllvd,
	vpsllvq,
	vpsllw,
	vpsrad,
	vpsraq,
	vpsravd,
	vpsravq,
	vpsraw,
	vpsrldq,
	vpsrld,
	vpsrlq,
	vpsrlvd,
	vpsrlvq,
	vpsrlw,
	vpsubb,
	vpsubd,
	vpsubq,
	vpsubsb,
	vpsubsw,
	vpsubusb,
	vpsubusw,
	vpsubw,
	vptestmd,
	vptestmq,
	vptestnmd,
	vptestnmq,
	vptest,
	vpunpckhbw,
	vpunpckhdq,
	vpunpckhqdq,
	vpunpckhwd,
	vpunpcklbw,
	vpunpckldq,
	vpunpcklqdq,
	vpunpcklwd,
	vpxord,
	vpxorq,
	vpxor,
	vrcp14pd,
	vrcp14ps,
	vrcp14sd,
	vrcp14ss,
	vrcp28pd,
	vrcp28ps,
	vrcp28sd,
	vrcp28ss,
	vrcpps,
	vrcpss,
	vrndscalepd,
	vrndscaleps,
	vrndscalesd,
	vrndscaless,
	vroundpd,
	vroundps,
	vroundsd,
	vroundss,
	vrsqrt14pd,
	vrsqrt14ps,
	vrsqrt14sd,
	vrsqrt14ss,
	vrsqrt28pd,
	vrsqrt28ps,
	vrsqrt28sd,
	vrsqrt28ss,
	vrsqrtps,
	vrsqrtss,
	vscatterdpd,
	vscatterdps,
	vscatterpf0dpd,
	vscatterpf0dps,
	vscatterpf0qpd,
	vscatterpf0qps,
	vscatterpf1dpd,
	vscatterpf1dps,
	vscatterpf1qpd,
	vscatterpf1qps,
	vscatterqpd,
	vscatterqps,
	vshufpd,
	vshufps,
	vsqrtpd,
	vsqrtps,
	vsqrtsd,
	vsqrtss,
	vstmxcsr,
	vsubpd,
	vsubps,
	vsubsd,
	vsubss,
	vtestpd,
	vtestps,
	vunpckhpd,
	vunpckhps,
	vunpcklpd,
	vunpcklps,
	vzeroall,
	vzeroupper,
	wait,
	wbinvd,
	wrfsbase,
	wrgsbase,
	wrmsr,
	xabort,
	xacquire,
	xbegin,
	xchg,
	xcryptcbc,
	xcryptcfb,
	xcryptctr,
	xcryptecb,
	xcryptofb,
	xend,
	xgetbv,
	xlatb,
	xrelease,
	xrstor,
	xrstor64,
	xrstors,
	xrstors64,
	xsave,
	xsave64,
	xsavec,
	xsavec64,
	xsaveopt,
	xsaveopt64,
	xsaves,
	xsaves64,
	xsetbv,
	xsha1,
	xsha256,
	xstore,
	xtest,
	fdisi8087_nop,
	feni8087_nop,

	// pseudo instructions
	cmpss,
	cmpeqss,
	cmpltss,
	cmpless,
	cmpunordss,
	cmpneqss,
	cmpnltss,
	cmpnless,
	cmpordss,

	cmpsd,
	cmpeqsd,
	cmpltsd,
	cmplesd,
	cmpunordsd,
	cmpneqsd,
	cmpnltsd,
	cmpnlesd,
	cmpordsd,

	cmpps,
	cmpeqps,
	cmpltps,
	cmpleps,
	cmpunordps,
	cmpneqps,
	cmpnltps,
	cmpnleps,
	cmpordps,

	cmppd,
	cmpeqpd,
	cmpltpd,
	cmplepd,
	cmpunordpd,
	cmpneqpd,
	cmpnltpd,
	cmpnlepd,
	cmpordpd,

	vcmpss,
	vcmpeqss,
	vcmpltss,
	vcmpless,
	vcmpunordss,
	vcmpneqss,
	vcmpnltss,
	vcmpnless,
	vcmpordss,
	vcmpeq_uqss,
	vcmpngess,
	vcmpngtss,
	vcmpfalsess,
	vcmpneq_oqss,
	vcmpgess,
	vcmpgtss,
	vcmptruess,
	vcmpeq_osss,
	vcmplt_oqss,
	vcmple_oqss,
	vcmpunord_sss,
	vcmpneq_usss,
	vcmpnlt_uqss,
	vcmpnle_uqss,
	vcmpord_sss,
	vcmpeq_usss,
	vcmpnge_uqss,
	vcmpngt_uqss,
	vcmpfalse_osss,
	vcmpneq_osss,
	vcmpge_oqss,
	vcmpgt_oqss,
	vcmptrue_usss,

	vcmpsd,
	vcmpeqsd,
	vcmpltsd,
	vcmplesd,
	vcmpunordsd,
	vcmpneqsd,
	vcmpnltsd,
	vcmpnlesd,
	vcmpordsd,
	vcmpeq_uqsd,
	vcmpngesd,
	vcmpngtsd,
	vcmpfalsesd,
	vcmpneq_oqsd,
	vcmpgesd,
	vcmpgtsd,
	vcmptruesd,
	vcmpeq_ossd,
	vcmplt_oqsd,
	vcmple_oqsd,
	vcmpunord_ssd,
	vcmpneq_ussd,
	vcmpnlt_uqsd,
	vcmpnle_uqsd,
	vcmpord_ssd,
	vcmpeq_ussd,
	vcmpnge_uqsd,
	vcmpngt_uqsd,
	vcmpfalse_ossd,
	vcmpneq_ossd,
	vcmpge_oqsd,
	vcmpgt_oqsd,
	vcmptrue_ussd,

	vcmpps,
	vcmpeqps,
	vcmpltps,
	vcmpleps,
	vcmpunordps,
	vcmpneqps,
	vcmpnltps,
	vcmpnleps,
	vcmpordps,
	vcmpeq_uqps,
	vcmpngeps,
	vcmpngtps,
	vcmpfalseps,
	vcmpneq_oqps,
	vcmpgeps,
	vcmpgtps,
	vcmptrueps,
	vcmpeq_osps,
	vcmplt_oqps,
	vcmple_oqps,
	vcmpunord_sps,
	vcmpneq_usps,
	vcmpnlt_uqps,
	vcmpnle_uqps,
	vcmpord_sps,
	vcmpeq_usps,
	vcmpnge_uqps,
	vcmpngt_uqps,
	vcmpfalse_osps,
	vcmpneq_osps,
	vcmpge_oqps,
	vcmpgt_oqps,
	vcmptrue_usps,

	vcmppd,
	vcmpeqpd,
	vcmpltpd,
	vcmplepd,
	vcmpunordpd,
	vcmpneqpd,
	vcmpnltpd,
	vcmpnlepd,
	vcmpordpd,
	vcmpeq_uqpd,
	vcmpngepd,
	vcmpngtpd,
	vcmpfalsepd,
	vcmpneq_oqpd,
	vcmpgepd,
	vcmpgtpd,
	vcmptruepd,
	vcmpeq_ospd,
	vcmplt_oqpd,
	vcmple_oqpd,
	vcmpunord_spd,
	vcmpneq_uspd,
	vcmpnlt_uqpd,
	vcmpnle_uqpd,
	vcmpord_spd,
	vcmpeq_uspd,
	vcmpnge_uqpd,
	vcmpngt_uqpd,
	vcmpfalse_ospd,
	vcmpneq_ospd,
	vcmpge_oqpd,
	vcmpgt_oqpd,
	vcmptrue_uspd,

	ud0,
	endbr32,
    endbr64,
}

/// Group of X86 instructions
enum  X86InstructionGroupId {
    invalid = 0,

	// Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	jump,
	// all call instructions
	call,
	// all return instructions
	ret,
	// all interrupt instructions (int+syscall)
	int_,
	// all interrupt return instructions
	iret,
	// all privileged instructions
	privilege,
	// all relative branching instructions
	branch_relative,

	// Architecture-specific groups
	vm = 128,	/// All virtualization instructions (VT-x + AMD-V)
	grp_3dnow,
	aes,
	adx,
	avx,
	avx2,
	avx512,
	bmi,
	bmi2,
	cmov,
	f16c,
	fma,
	fma4,
	fsgsbase,
	hle,
	mmx,
	mode32,
	mode64,
	rtm,
	sha,
	sse1,
	sse2,
	sse3,
	sse41,
	sse42,
	sse4a,
	ssse3,
	pclmul,
	xop,
	cdi,
	eri,
	tbm,
	grp_16bitmode,
	not64bitmode,
	sgx,
	dqi,
	bwi,
	pfi,
	vlx,
	smap,
	novlx,
    fpu,
}