module capstone.arm;

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
class ArmRegister : RegisterImpl!ArmRegisterId {
    this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class ArmInstructionGroup : InstructionGroupImpl!ArmInstructionGroupId {
    this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class ArmDetail : DetailImpl!(ArmRegister, ArmInstructionGroup, ArmInstructionDetail) {
    this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class ArmInstruction : InstructionImpl!(ArmInstructionId, ArmRegister, ArmDetail) {
    this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneArm : CapstoneImpl!(ArmInstructionId, ArmInstruction) {
    this(in ModeFlags modeFlags){
        super(Arch.arm, modeFlags);
    }
}

/** Instruction's operand referring to memory

This is associated with the `ArmOpType.mem` operand type
*/
struct ArmOpMem {
    ArmRegister base;   /// Base register
    ArmRegister index;  /// Index register
    int scale;          /// Scale for index register (can be 1, or -1)
    int disp;           /// Displacement value
	int lshift;         /// Left-shift on index register, or 0 if irrelevant.

    this(in Capstone cs, arm_op_mem internal){
        base = new ArmRegister(cs, internal.base);
        index = new ArmRegister(cs, internal.index);
        scale = internal.scale;
        disp = internal.disp;
        lshift = internal.lshift;
    }
}

/// Optional shift
struct ArmShift{
    ArmShiftType type;  /// Type of shift
    uint value;         /// value (constant or register) to shift by

    this(cs_arm_op.Shift internal){
        type = internal.type.to!ArmShiftType;
        value = internal.value;
    }
}

/** Union of possible operand values
 *
 * Note: In contrast to the C API, this union distinguishes registers and system registers
 */
union ArmOpValue{
    ArmRegister reg;        /// Register
    ArmSysreg sysreg;       /// MSR/MRS special register
    int imm;                /// Immediate
    double fp;              /// Floating-point
    ArmOpMem mem;           /// Memory
    ArmSetendType setend;   /// Setend
}

/// Instruction's operand
struct ArmOp {
    int vectorIndex;  /// Vector index for some vector operands (or -1 if irrelevant)
    ArmShift shift;   /// Potential shifting of operand
    ArmOpType type;   /// Operand type
    SafeUnion!ArmOpValue value; /// Operand value of type `type`
    alias value this; /// Convenient access to value (as in original bindings)

    /** In some instructions, an operand can be subtracted or added to the base register.

    If TRUE, this operand is subtracted. Otherwise, it is added.
    */
    bool subtracted;

	/** How is this operand accessed? (READ, WRITE or READ|WRITE)

	NOTE: This field is irrelevant, i.e. equals 0, if engine is compiled in DIET mode.
    */
	AccessFlags access;

	/// Neon lane index for NEON instructions (or -1 if irrelevant)
    byte neonLane;

    package this(in Capstone cs, cs_arm_op internal){
        vectorIndex = internal.vector_index;
        shift = internal.shift.to!ArmShift;
        type = internal.type.to!ArmOpType;
        final switch(internal.type){
            case ArmOpType.invalid:
                break;
            case ArmOpType.reg:
                value.reg = new ArmRegister(cs, internal.reg);
                break;
            case ArmOpType.sysreg:
                value.sysreg = internal.reg.to!ArmSysreg;
                break;
            case ArmOpType.imm, ArmOpType.cimm, ArmOpType.pimm:
                value.imm = internal.imm;
                break;
            case ArmOpType.mem:
                value.mem = ArmOpMem(cs, internal.mem);
                break;
            case ArmOpType.fp:
                value.fp = internal.fp;
                break;
            case ArmOpType.setend:
                value.setend = internal.setend.to!ArmSetendType;
                break;
        }
        subtracted = internal.subtracted;
        access = cast(AccessType)internal.access;
        neonLane = internal.neon_lane;
    }
}

/// ARM-specific information about an instruction
struct ArmInstructionDetail {
    bool usermode;                /// User-mode registers to be loaded (for LDM/STM instructions)
    int vectorSize;               /// Scalar size for vector instructions
    ArmVectordataType vectorData; /// Data type for elements of vector instructions
    ArmCpsmodeType cpsMode;       /// Mode operand for CPS instruction
    ArmCpsflagType cpsFlag;       /// Flags operand for CPS instruction
    ArmCc cc;                     /// Conditional code for this instruction
    bool updateFlags;             /// Does this instruction update flags?
    bool writeback;               /// Does this instruction write-back?
    ArmMemBarrier memBarrier;     /// Option for some memory barrier instructions

    ArmOp[] operands;             /// Operands for this instruction.

    package this(in Capstone cs, cs_arch_detail arch_detail) {
        auto internal = arch_detail.arm;
        usermode = internal.usermode;
        vectorSize = internal.vector_size;
        vectorData = internal.vector_data.to!ArmVectordataType;
        cpsMode = internal.cps_mode.to!ArmCpsmodeType;
        cpsFlag = internal.cps_flag.to!ArmCpsflagType;
        cc = internal.cc.to!ArmCc;
        updateFlags = internal.update_flags;
        writeback = internal.writeback;
        memBarrier = internal.mem_barrier.to!ArmMemBarrier;

        foreach(op; internal.operands[0..internal.op_count])
            operands ~= ArmOp(cs, op);
    }
}

//=============================================================================
// Constants
//=============================================================================

/// ARM shift type
enum ArmShiftType {
    invalid = 0, /// Invalid
    asr,         /// Arithmetic shift right (with immediate const)
    lsl,         /// Logical shift left (with immediate const)
    lsr,         /// Logical shift right (with immediate const)
    ror,         /// Rotate right (with immediate const)
    rrx,         /// Rotate right with extend (with immediate const)
    asr_reg,     /// Arithmetic shift right (with register)
    lsl_reg,     /// Logical shift left (with register)
    lsr_reg,     /// Logical shift right (with register)
    ror_reg,     /// Rotate right (with register)
    rrx_reg,     /// Rotate right with extend (with register)
}

/// ARM condition code
enum ArmCc {
    invalid = 0, /// Invalid
    eq,          /// Equal                      Equal
    ne,          /// Not equal                  Not equal, or unordered
    hs,          /// Carry set                  >, ==, or unordered
    lo,          /// Carry clear                Less than
    mi,          /// Minus, negative            Less than
    pl,          /// Plus, positive or zero     >, ==, or unordered
    vs,          /// Overflow                   Unordered
    vc,          /// No overflow                Not unordered
    hi,          /// Unsigned higher            Greater than, or unordered
    ls,          /// Unsigned lower or same     Less than or equal
    ge,          /// Greater than or equal      Greater than or equal
    lt,          /// Less than                  Less than, or unordered
    gt,          /// Greater than               Greater than
    le,          /// Less than or equal         <, ==, or unordered
    al           /// Always (unconditional)     Always (unconditional)
}

/// System registers for MSR
enum ArmSysreg {
    invalid = 0,

    // SPSR* registers can be OR combined
    spsr_c = 1,
    spsr_x = 2,
    spsr_xc = 3,
    spsr_s = 4,
    spsr_sc = 5,
    spsr_sx = 6,
    spsr_sxc = 7,
    spsr_f = 8,
    spsr_fc = 9,
    spsr_fx = 10,
    spsr_fxc = 11,
    spsr_fs = 12,
    spsr_fsc = 13,
    spsr_fsx = 14,
    spsr_fsxc = 15,

    // CPSR* registers can be OR combined
    cpsr_c = 16,
    cpsr_x = 32,
    cpsr_xc = 48,
    cpsr_s = 64,
    cpsr_sc = 80,
    cpsr_sx = 96,
    cpsr_sxc = 112,
    cpsr_f = 128,
    cpsr_fc = 144,
    cpsr_fx = 160,
    cpsr_fxc = 176,
    cpsr_fs = 192,
    cpsr_fsc = 208,
    cpsr_fsx = 224,
    cpsr_fsxc = 240,

    // Independent registers
    apsr = 256,
    apsr_g,
    apsr_nzcvq,
    apsr_nzcvqg,

    iapsr,
    iapsr_g,
    iapsr_nzcvqg,

    eapsr,
    eapsr_g,
    eapsr_nzcvqg,

    xpsr,
    xpsr_g,
    xpsr_nzcvqg,

    ipsr,
    epsr,
    iepsr,

    msp,
    psp,
    primask,
    basepri,
    basepri_max,
    faultmask,
    control,

    // Banked Registers
    r8_usr,
    r9_usr,
    r10_usr,
    r11_usr,
    r12_usr,
    sp_usr,
    lr_usr,
    r8_fiq,
    r9_fiq,
    r10_fiq,
    r11_fiq,
    r12_fiq,
    sp_fiq,
    lr_fiq,
    lr_irq,
    sp_irq,
    lr_svc,
    sp_svc,
    lr_abt,
    sp_abt,
    lr_und,
    sp_und,
    lr_mon,
    sp_mon,
    elr_hyp,
    sp_hyp,
    
    spsr_fiq,
    spsr_irq,
    spsr_svc,
    spsr_abt,
    spsr_und,
    spsr_mon,
    spsr_hyp,
}

/// The memory barrier constants map directly to the 4-bit encoding of the option field for Memory Barrier operations
enum ArmMemBarrier {
    invalid = 0,
    reserved_0,
    oshld,
    oshst,
    osh,
    reserved_4,
    nshld,
    nshst,
    nsh,
    reserved_8,
    ishld,
    ishst,
    ish,
    reserved_12,
    ld,
    st,
    sy,
}

/// Operand type for instruction's operands
enum ArmOpType {
    invalid = 0, /// Invalid
    reg,         /// Register operand (`ArmRegister`)
    imm,         /// Immediate operand (`int`)
    mem,         /// Memory operand (`ArmOpMem`)
    fp,          /// Floating-Point operand (`double`).
    cimm = 64,   /// C-Immediate (`int` / coprocessor registers)
    pimm,        /// P-Immediate (`int` / coprocessor registers)
    setend,      /// Operand for SETEND instruction (`ArmSetendType`)
    sysreg,      /// MSR/MRS system register operand (`ArmRegister`)
}

/// Operand type for SETEND instruction
enum ArmSetendType {
    invalid = 0, /// Invalid
    be,          /// Big-endian operand
    le,          /// Little-endian operand
}

/// Mode operand of CPS instruction
enum ArmCpsmodeType {
    invalid = 0, /// Invalid
    ie = 2,      /// Interrupt or abort enable
    id = 3       /// Interrupt or abort disable
}

/// Flags operand of CPS instruction
enum ArmCpsflagType {
    invalid = 0, /// Invalid
    f = 1,       /// Enables or disables FIQ interrupts
    i = 2,       /// Enables or disables IRQ interrupts
    a = 4,       /// Enables or disables imprecise aborts
    none = 16,   /// No flag
}

/// Data type for elements of vector instructions.
enum ArmVectordataType {
    invalid = 0,

    // Integer type
    i8,
    i16,
    i32,
    i64,

    // Signed integer type
    s8,
    s16,
    s32,
    s64,

    // Unsigned integer type
    u8,
    u16,
    u32,
    u64,

    // Data type for VMUL/VMULL
    p8,

    // Floating type
    f32,
    f64,

    // Convert float <-> float
    f16f64, // f16.f64
    f64f16, // f64.f16
    f32f16, // f32.f16
    f16f32, // f32.f16
    f64f32, // f64.f32
    f32f64, // f32.f64

    // Convert integer <-> float
    s32f32, // s32.f32
    u32f32, // u32.f32
    f32s32, // f32.s32
    f32u32, // f32.u32
    f64s16, // f64.s16
    f32s16, // f32.s16
    f64s32, // f64.s32
    s16f64, // s16.f64
    s16f32, // s16.f64
    s32f64, // s32.f64
    u16f64, // u16.f64
    u16f32, // u16.f32
    u32f64, // u32.f64
    f64u16, // f64.u16
    f32u16, // f32.u16
    f64u32, // f64.u32
}

/// ARM registers
enum ArmRegisterId {
    invalid = 0,
    apsr,
    apsr_nzcv,
    cpsr,
    fpexc,
    fpinst,
    fpscr,
    fpscr_nzcv,
    fpsid,
    itstate,
    lr,
    pc,
    sp,
    spsr,
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
    fpinst2,
    mvfr0,
    mvfr1,
    mvfr2,
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
    r0,
    r1,
    r2,
    r3,
    r4,
    r5,
    r6,
    r7,
    r8,
    r9,
    r10,
    r11,
    r12,
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

    // Alias registers
    r13 = sp,
    r14 = lr,
    r15 = pc,

    sb = r9,
    sl = r10,
    fp = r11,
    ip = r12,
}

/// ARM instruction
enum ArmInstructionId {
    invalid = 0,

    adc,
    add,
    adr,
    aesd,
    aese,
    aesimc,
    aesmc,
    and,
    bfc,
    bfi,
    bic,
    bkpt,
    bl,
    blx,
    bx,
    bxj,
    b,
    cdp,
    cdp2,
    clrex,
    clz,
    cmn,
    cmp,
    cps,
    crc32b,
    crc32cb,
    crc32ch,
    crc32cw,
    crc32h,
    crc32w,
    dbg,
    dmb,
    dsb,
    eor,
    vmov,
    fldmdbx,
    fldmiax,
    vmrs,
    fstmdbx,
    fstmiax,
    hint,
    hlt,
    isb,
    lda,
    ldab,
    ldaex,
    ldaexb,
    ldaexd,
    ldaexh,
    ldah,
    ldc2l,
    ldc2,
    ldcl,
    ldc,
    ldmda,
    ldmdb,
    ldm,
    ldmib,
    ldrbt,
    ldrb,
    ldrd,
    ldrex,
    ldrexb,
    ldrexd,
    ldrexh,
    ldrh,
    ldrht,
    ldrsb,
    ldrsbt,
    ldrsh,
    ldrsht,
    ldrt,
    ldr,
    mcr,
    mcr2,
    mcrr,
    mcrr2,
    mla,
    mls,
    mov,
    movt,
    movw,
    mrc,
    mrc2,
    mrrc,
    mrrc2,
    mrs,
    msr,
    mul,
    mvn,
    orr,
    pkhbt,
    pkhtb,
    pldw,
    pld,
    pli,
    qadd,
    qadd16,
    qadd8,
    qasx,
    qdadd,
    qdsub,
    qsax,
    qsub,
    qsub16,
    qsub8,
    rbit,
    rev,
    rev16,
    revsh,
    rfeda,
    rfedb,
    rfeia,
    rfeib,
    rsb,
    rsc,
    sadd16,
    sadd8,
    sasx,
    sbc,
    sbfx,
    sdiv,
    sel,
    setend,
    sha1c,
    sha1h,
    sha1m,
    sha1p,
    sha1su0,
    sha1su1,
    sha256h,
    sha256h2,
    sha256su0,
    sha256su1,
    shadd16,
    shadd8,
    shasx,
    shsax,
    shsub16,
    shsub8,
    smc,
    smlabb,
    smlabt,
    smlad,
    smladx,
    smlal,
    smlalbb,
    smlalbt,
    smlald,
    smlaldx,
    smlaltb,
    smlaltt,
    smlatb,
    smlatt,
    smlawb,
    smlawt,
    smlsd,
    smlsdx,
    smlsld,
    smlsldx,
    smmla,
    smmlar,
    smmls,
    smmlsr,
    smmul,
    smmulr,
    smuad,
    smuadx,
    smulbb,
    smulbt,
    smull,
    smultb,
    smultt,
    smulwb,
    smulwt,
    smusd,
    smusdx,
    srsda,
    srsdb,
    srsia,
    srsib,
    ssat,
    ssat16,
    ssax,
    ssub16,
    ssub8,
    stc2l,
    stc2,
    stcl,
    stc,
    stl,
    stlb,
    stlex,
    stlexb,
    stlexd,
    stlexh,
    stlh,
    stmda,
    stmdb,
    stm,
    stmib,
    strbt,
    strb,
    strd,
    strex,
    strexb,
    strexd,
    strexh,
    strh,
    strht,
    strt,
    str,
    sub,
    svc,
    swp,
    swpb,
    sxtab,
    sxtab16,
    sxtah,
    sxtb,
    sxtb16,
    sxth,
    teq,
    trap,
    tst,
    uadd16,
    uadd8,
    uasx,
    ubfx,
    udf,
    udiv,
    uhadd16,
    uhadd8,
    uhasx,
    uhsax,
    uhsub16,
    uhsub8,
    umaal,
    umlal,
    umull,
    uqadd16,
    uqadd8,
    uqasx,
    uqsax,
    uqsub16,
    uqsub8,
    usad8,
    usada8,
    usat,
    usat16,
    usax,
    usub16,
    usub8,
    uxtab,
    uxtab16,
    uxtah,
    uxtb,
    uxtb16,
    uxth,
    vabal,
    vaba,
    vabdl,
    vabd,
    vabs,
    vacge,
    vacgt,
    vadd,
    vaddhn,
    vaddl,
    vaddw,
    vand,
    vbic,
    vbif,
    vbit,
    vbsl,
    vceq,
    vcge,
    vcgt,
    vcle,
    vcls,
    vclt,
    vclz,
    vcmp,
    vcmpe,
    vcnt,
    vcvta,
    vcvtb,
    vcvt,
    vcvtm,
    vcvtn,
    vcvtp,
    vcvtt,
    vdiv,
    vdup,
    veor,
    vext,
    vfma,
    vfms,
    vfnma,
    vfnms,
    vhadd,
    vhsub,
    vld1,
    vld2,
    vld3,
    vld4,
    vldmdb,
    vldmia,
    vldr,
    vmaxnm,
    vmax,
    vminnm,
    vmin,
    vmla,
    vmlal,
    vmls,
    vmlsl,
    vmovl,
    vmovn,
    vmsr,
    vmul,
    vmull,
    vmvn,
    vneg,
    vnmla,
    vnmls,
    vnmul,
    vorn,
    vorr,
    vpadal,
    vpaddl,
    vpadd,
    vpmax,
    vpmin,
    vqabs,
    vqadd,
    vqdmlal,
    vqdmlsl,
    vqdmulh,
    vqdmull,
    vqmovun,
    vqmovn,
    vqneg,
    vqrdmulh,
    vqrshl,
    vqrshrn,
    vqrshrun,
    vqshl,
    vqshlu,
    vqshrn,
    vqshrun,
    vqsub,
    vraddhn,
    vrecpe,
    vrecps,
    vrev16,
    vrev32,
    vrev64,
    vrhadd,
    vrinta,
    vrintm,
    vrintn,
    vrintp,
    vrintr,
    vrintx,
    vrintz,
    vrshl,
    vrshrn,
    vrshr,
    vrsqrte,
    vrsqrts,
    vrsra,
    vrsubhn,
    vseleq,
    vselge,
    vselgt,
    vselvs,
    vshll,
    vshl,
    vshrn,
    vshr,
    vsli,
    vsqrt,
    vsra,
    vsri,
    vst1,
    vst2,
    vst3,
    vst4,
    vstmdb,
    vstmia,
    vstr,
    vsub,
    vsubhn,
    vsubl,
    vsubw,
    vswp,
    vtbl,
    vtbx,
    vcvtr,
    vtrn,
    vtst,
    vuzp,
    vzip,
    addw,
    asr,
    dcps1,
    dcps2,
    dcps3,
    it,
    lsl,
    lsr,
    asrs,
    lsrs,
    orn,
    ror,
    rrx,
    subs,
    subw,
    tbb,
    tbh,
    cbnz,
    cbz,
    movs,
    pop,
    push,

    // Special instructions
    nop,
    yield,
    wfe,
    wfi,
    sev,
    sevl,
    vpush,
    vpop
}

/// Group of ARM instructions
enum ArmInstructionGroupId {
    invalid = 0,

	// Generic groups
	// All jump instructions (conditional+direct+indirect jumps)
	jump,
	call,
	int_ = 4,
	privilege = 6,
	branch_relative,

	// Architecture-specific groups
	crypto = 128,
	databarrier,
	divide,
	fparmv8,
	multpro,
	neon,
	t2extractpack,
	thumb2dsp,
	trustzone,
	v4t,
	v5t,
	v5te,
	v6,
	v6t2,
	v7,
	v8,
	vfp2,
	vfp3,
	vfp4,
	arm,
	mclass,
	notmclass,
	thumb,
	thumb1only,
	thumb2,
	prev8,
	fpvmlx,
	mulops,
	crc,
	dpvfp,
	v6m,
    virtualization,
}