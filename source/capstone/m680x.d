/// Types and constants of M680x architecture
module capstone.m680x;

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
class M680xRegister : RegisterImpl!M680xRegisterId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class M680xInstructionGroup : InstructionGroupImpl!M680xInstructionGroupId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class M680xDetail : DetailImpl!(M680xRegister, M680xInstructionGroup, M680xInstructionDetail) {
    package this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class M680xInstruction : InstructionImpl!(M680xInstructionId, M680xRegister, M680xDetail) {
    package this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneM680x : CapstoneImpl!(M680xInstructionId, M680xInstruction) {
    /** Creates an architecture-specific instance with a given mode of interpretation
    
    Params:
        modeFlags = The (initial) mode of interpretation, which can still be changed later on
    */
	this(in ModeFlags modeFlags){
        super(Arch.m680x, modeFlags);
    }
}

/// Instruction's operand referring to indexed addressing
struct M680xOpIdx {
	M680xRegister baseReg;	  /// Base register (or `M680xRegisterId.invalid` if irrelevant)
	M680xRegister offsetReg;  /// Offset register (or `M680xRegisterId.invalid` if irrelevant)
	short offset;	  		  /// 5-,8- or 16-bit offset
	ushort offsetAddr;		  /// = offset addr. if baseReg.id == M680xRegisterId.pc. Calculated as offset + PC
	M680xOffsetBits offsetBits;	/// Offset width in bits for indexed addressing
	byte incDec;			  /// Inc. or dec. value: 0: no inc-/decrement, 1 .. 8: increment by 1 .. 8, -1 .. -8: decrement by 1 .. 8.
							  /// If flag M680xFlag.postIncDec set it is post inc-/decrement otherwise pre inc-/decrement
	BitFlags!M680xFlag flags; /// 8-bit flags (see above)

	package this(in Capstone cs, m680x_op_idx internal) {
		baseReg = new M680xRegister(cs, internal.base_reg);
		offsetReg = new M680xRegister(cs, internal.offset_reg);
		offset = internal.offset;
		offsetAddr = internal.offset_addr;
		offsetBits = internal.offset_bits.to!M680xOffsetBits;
		incDec = internal.inc_dec;
		flags = cast(M680xFlag)internal.flags;
	}
}

/// Instruction's memory operand referring to relative addressing (Bcc/LBcc)
struct M680xOpRel {
	ushort address;	/// The absolute address. Calculated as PC + offset. PC is the first address after the instruction.
	short offset;	/// The offset/displacement value

	package this(m680x_op_rel internal) {
		address = internal.address;
		offset = internal.offset;
	}
}

/// Instruction's operand referring to extended addressing
struct M680xOpExt {
	ushort address; /// The absolute address
	bool indirect;  /// true if extended indirect addressing

	package this(m680x_op_ext internal) {
		address = internal.address;
		indirect = internal.indirect;
	}
}

/// Union of possible operand types
union M680xOpValue{
	int imm;			/// Immediate value for IMM operand
	M680xRegister reg;	/// Register value for REG operand
	M680xOpIdx idx;		/// Indexed addressing operand
	M680xOpRel rel;		/// Relative address. operand (Bcc/LBcc)
	M680xOpExt ext;		/// Extended address
	ubyte directAddr;	/// Direct address (lower 8-bit)
	ubyte constVal; 	/// Constant value (bit index, page nr.)
}

/// Instruction's operand
struct M680xOp {
	M680xOpType type;             /// Operand type
    SafeUnion!M680xOpValue value; /// Operand value of type `type`
    alias value this;             /// Convenient access to value (as in original bindings)

	ubyte size; /// Size of this operand (in bytes)
	
	/** How is this operand accessed? (READ, WRITE or READ|WRITE)

	NOTE: This field is irrelevant, i.e. equals 0, if engine is compiled in DIET mode.
    */
	AccessFlags access;

    package this(in Capstone cs, cs_m680x_op internal) {
        type = internal.type.to!M680xOpType;
		final switch(type) {
			case M680xOpType.invalid:
				break;
			case M680xOpType.register:
				value.reg = new M680xRegister(cs, internal.reg);
				break;
			case M680xOpType.immediate:
				value.imm = internal.imm;
				break;
			case M680xOpType.indexed:
				value.idx = M680xOpIdx(cs, internal.idx);
				break;
			case M680xOpType.extended:
				value.ext = M680xOpExt(internal.ext);
				break;
			case M680xOpType.direct:
				value.directAddr = internal.direct_addr;
				break;
			case M680xOpType.relative:
				value.rel = M680xOpRel(internal.rel);
				break;
			case M680xOpType.constant:
				value.constVal = internal.const_val;
				break;
		}
		size = internal.size;
        access = cast(AccessType)internal.access;
	}
}

/// M680x-specific information about an instruction
struct M680xInstructionDetail {
	M680xOp[] operands; 				 /// Operands for this instruction
	BitFlags!M680xInstructionFlag flags; /// See `M680xInstructionFlag`

	package this(in Capstone cs, cs_arch_detail arch_detail){
        auto internal = arch_detail.m680x;
        foreach(op; internal.operands[0..internal.op_count])
            operands ~= M680xOp(cs, op);
		flags = cast(M680xInstructionFlag)internal.flags;
    }
}

//=============================================================================
// Constants
//=============================================================================

/// Operand type for instruction's operands
enum M680xOpType {
	invalid = 0, /// Uninitialized
	register,    /// Register operand
	immediate,   /// Immediate operand
	indexed,     /// Indexed addressing operand
	extended,    /// Extended addressing operand
	direct,      /// Direct addressing operand
	relative,    /// Relative addressing operand
	constant,    /// Constant operand (Displayed as number only). Used e.g. for a bit index or page number.
}

/// Supported bit values for `M680xOpIdx.offsetBits`
enum M680xOffsetBits {
	none = 0,
	_5 = 5,
	_8 = 8,
	_9 = 9,
	_16 = 16
}

/// Supported bit flags for `M680xOpIdx.flags`
enum M680xFlag {
	indirect = 1,
	noComma = 2,
	postIncDec = 4
}

/// M680X instruction flags:
enum M680xInstructionFlag {
	firstOpInMnem = 1, /// The first (register) operand is part of the instruction mnemonic
	secondOpInMnem = 2 /// The second (register) operand is part of the instruction mnemonic
}

/// M680X registers and special registers
enum M680xRegisterId {
	invalid = 0,

	a, /// M6800/1/2/3/9, HD6301/9
	b, /// M6800/1/2/3/9, HD6301/9
	e, /// HD6309
	f, /// HD6309
	_0, /// HD6309

	d, /// M6801/3/9, HD6301/9
	w, /// HD6309

	cc, /// M6800/1/2/3/9, M6301/9
	dp, /// M6809/M6309
	md, /// M6309

	hx, /// M6808
	h, /// M6808
	x, /// M6800/1/2/3/9, M6301/9
	y, /// M6809/M6309
	s, /// M6809/M6309
	u, /// M6809/M6309
	v, /// M6309

	q, /// M6309

	pc, /// M6800/1/2/3/9, M6301/9

	tmp2, /// CPU12
	tmp3, /// CPU12
}

/// M680X instruction IDs
enum M680xInstructionId {
	invld = 0,
	aba, /// M6800/1/2/3
	abx,
	aby,
	adc,
	adca,
	adcb,
	adcd,
	adcr,
	add,
	adda,
	addb,
	addd,
	adde,
	addf,
	addr,
	addw,
	aim,
	ais,
	aix,
	and,
	anda,
	andb,
	andcc,
	andd,
	andr,
	asl,
	asla,
	aslb,
	asld, /// or LSLD
	asr,
	asra,
	asrb,
	asrd,
	asrx,
	band,
	bcc, /// or BHS
	bclr,
	bcs, /// or BLO
	beor,
	beq,
	bge,
	bgnd,
	bgt,
	bhcc,
	bhcs,
	bhi,
	biand,
	bieor,
	bih,
	bil,
	bior,
	bit,
	bita,
	bitb,
	bitd,
	bitmd,
	ble,
	bls,
	blt,
	bmc,
	bmi,
	bms,
	bne,
	bor,
	bpl,
	brclr,
	brset,
	bra,
	brn,
	bset,
	bsr,
	bvc,
	bvs,
	call,
	cba, /// M6800/1/2/3
	cbeq,
	cbeqa,
	cbeqx,
	clc, /// M6800/1/2/3
	cli, /// M6800/1/2/3
	clr,
	clra,
	clrb,
	clrd,
	clre,
	clrf,
	clrh,
	clrw,
	clrx,
	clv, /// M6800/1/2/3
	cmp,
	cmpa,
	cmpb,
	cmpd,
	cmpe,
	cmpf,
	cmpr,
	cmps,
	cmpu,
	cmpw,
	cmpx,
	cmpy,
	com,
	coma,
	comb,
	comd,
	come,
	comf,
	comw,
	comx,
	cpd,
	cphx,
	cps,
	cpx, /// M6800/1/2/3
	cpy,
	cwai,
	daa,
	dbeq,
	dbne,
	dbnz,
	dbnza,
	dbnzx,
	dec,
	deca,
	decb,
	decd,
	dece,
	decf,
	decw,
	decx,
	des, /// M6800/1/2/3
	dex, /// M6800/1/2/3
	dey,
	div,
	divd,
	divq,
	ediv,
	edivs,
	eim,
	emacs,
	emaxd,
	emaxm,
	emind,
	eminm,
	emul,
	emuls,
	eor,
	eora,
	eorb,
	eord,
	eorr,
	etbl,
	exg,
	fdiv,
	ibeq,
	ibne,
	idiv,
	idivs,
	illgl,
	inc,
	inca,
	incb,
	incd,
	ince,
	incf,
	incw,
	incx,
	ins, /// M6800/1/2/3
	inx, /// M6800/1/2/3
	iny,
	jmp,
	jsr,
	lbcc, /// or LBHS
	lbcs, /// or LBLO
	lbeq,
	lbge,
	lbgt,
	lbhi,
	lble,
	lbls,
	lblt,
	lbmi,
	lbne,
	lbpl,
	lbra,
	lbrn,
	lbsr,
	lbvc,
	lbvs,
	lda,
	ldaa, /// M6800/1/2/3
	ldab, /// M6800/1/2/3
	ldb,
	ldbt,
	ldd,
	lde,
	ldf,
	ldhx,
	ldmd,
	ldq,
	lds,
	ldu,
	ldw,
	ldx,
	ldy,
	leas,
	leau,
	leax,
	leay,
	lsl,
	lsla,
	lslb,
	lsld,
	lslx,
	lsr,
	lsra,
	lsrb,
	lsrd, /// or ASRD
	lsrw,
	lsrx,
	maxa,
	maxm,
	mem,
	mina,
	minm,
	mov,
	movb,
	movw,
	mul,
	muld,
	neg,
	nega,
	negb,
	negd,
	negx,
	nop,
	nsa,
	oim,
	ora,
	oraa, /// M6800/1/2/3
	orab, /// M6800/1/2/3
	orb,
	orcc,
	ord,
	orr,
	psha, /// M6800/1/2/3
	pshb, /// M6800/1/2/3
	pshc,
	pshd,
	pshh,
	pshs,
	pshsw,
	pshu,
	pshuw,
	pshx, /// M6800/1/2/3
	pshy,
	pula, /// M6800/1/2/3
	pulb, /// M6800/1/2/3
	pulc,
	puld,
	pulh,
	puls,
	pulsw,
	pulu,
	puluw,
	pulx, /// M6800/1/2/3
	puly,
	rev,
	revw,
	rol,
	rola,
	rolb,
	rold,
	rolw,
	rolx,
	ror,
	rora,
	rorb,
	rord,
	rorw,
	rorx,
	rsp,
	rtc,
	rti,
	rts,
	sba, /// M6800/1/2/3
	sbc,
	sbca,
	sbcb,
	sbcd,
	sbcr,
	sec,
	sei,
	sev,
	sex,
	sexw,
	slp,
	sta,
	staa, /// M6800/1/2/3
	stab, /// M6800/1/2/3
	stb,
	stbt,
	std,
	ste,
	stf,
	stop,
	sthx,
	stq,
	sts,
	stu,
	stw,
	stx,
	sty,
	sub,
	suba,
	subb,
	subd,
	sube,
	subf,
	subr,
	subw,
	swi,
	swi2,
	swi3,
	sync,
	tab, /// M6800/1/2/3
	tap, /// M6800/1/2/3
	tax,
	tba, /// M6800/1/2/3
	tbeq,
	tbl,
	tbne,
	test,
	tfm,
	tfr,
	tim,
	tpa, /// M6800/1/2/3
	tst,
	tsta,
	tstb,
	tstd,
	tste,
	tstf,
	tstw,
	tstx,
	tsx, /// M6800/1/2/3
	tsy,
	txa,
	txs, /// M6800/1/2/3
	tys,
	wai, /// M6800/1/2/3
	wait,
	wav,
	wavr,
	xgdx, /// HD6301
	xgdy,
}

/// Group of M680X instructions
enum M680xInstructionGroupId {
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
	priv,
	// all relative branching instructions
	brarel,
}