/// Types and constants of TMS320C64x architecture
module capstone.tms320c64x;

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
class Tms320c64xRegister : RegisterImpl!Tms320c64xRegisterId {
    this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class Tms320c64xInstructionGroup : InstructionGroupImpl!Tms320c64xInstructionGroupId {
    this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class Tms320c64xDetail : DetailImpl!(Tms320c64xRegister, Tms320c64xInstructionGroup, Tms320c64xInstructionDetail) {
    this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class Tms320c64xInstruction : InstructionImpl!(Tms320c64xInstructionId, Tms320c64xRegister, Tms320c64xDetail) {
    this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneTms320c64x : CapstoneImpl!(Tms320c64xInstructionId, Tms320c64xInstruction) {
    this(in ModeFlags modeFlags){
        super(Arch.tms320c64x, modeFlags);
    }
}

/// Union of possible displacement values
union Tms320c64xDispValue {
	uint constant;				 // Constant displacement/offset
	Tms320c64xRegister register; // Register stating displacement/offset
}

/** Instruction's operand referring to memory

This is associated with the `Tms320c64xOpType.mem` operand type
*/
struct Tms320c64xOpMem {
	Tms320c64xRegister base; 	/// Base register
	SafeUnion!Tms320c64xDispValue disp;	/// Displacement/offset value
	uint unit;				 	/// Unit of base and offset register
	uint scaled;			 	/// Offset scaled
	Tms320c64xMemDisp disptype;	/// Displacement type
	Tms320c64xMemDir direction;	/// Direction
	Tms320c64xMemMod modify; 	/// Modification

	this(in Capstone cs, tms320c64x_op_mem internal) {
		base = new Tms320c64xRegister(cs, internal.base);
		unit = internal.unit;
		scaled = internal.scaled;
		disptype = internal.disptype.to!Tms320c64xMemDisp;
		if(disptype == Tms320c64xMemDisp.register)
			disp.register = new Tms320c64xRegister(cs, internal.disp);
		else
			disp.constant = internal.disp;
		direction = internal.direction.to!Tms320c64xMemDir;
		modify = internal.modify.to!Tms320c64xMemMod;
	}
}

/// Union of possible operand types
union Tms320c64xOpValue{
    Tms320c64xRegister reg; /// Register
    int imm;				/// Immediate
    Tms320c64xOpMem mem;	/// Memory
    Tms320c64xRegister[2] regpair; /// Register pair
}

/// Instruction's operand
struct Tms320c64xOp {
    Tms320c64xOpType type;   /// Operand type
    SafeUnion!Tms320c64xOpValue value; /// Operand value of type `type`
    alias value this;  /// Convenient access to value (as in original bindings)

    package this(in Capstone cs, cs_tms320c64x_op internal){
        type = internal.type.to!Tms320c64xOpType;
        final switch(internal.type) {
            case Tms320c64xOpType.invalid:
                break;
            case Tms320c64xOpType.reg:
                value.reg = new Tms320c64xRegister(cs, internal.reg);
                break;
            case Tms320c64xOpType.imm:
                value.imm = internal.imm;
                break;
            case Tms320c64xOpType.mem:
                value.mem = Tms320c64xOpMem(cs, internal.mem);
                break;
			case Tms320c64xOpType.regpair:
				value.regpair = [new Tms320c64xRegister(cs, internal.reg), new Tms320c64xRegister(cs, internal.reg+1)];
				break;
        }
    }
}

struct Tms320c64xCondition {
	Tms320c64xRegister reg;
	uint zero;

	this(in Capstone cs, cs_tms320c64x_condition internal) {
		reg = new Tms320c64xRegister(cs, internal.reg);
		zero = internal.zero;
	}
}

struct Tms320c64xFunit {
	Tms320c64xFunitType unit;
	uint side;
	uint crosspath;

	this(cs_tms320c64x_funit internal) {
		unit = internal.unit.to!Tms320c64xFunitType;
		side = internal.side;
		crosspath = internal.crosspath;
	}
}

/// TMS320C64x-specific information about an instruction
struct Tms320c64xInstructionDetail {
    Tms320c64xOp[] operands; /// Operands for this instruction.
	Tms320c64xCondition condition;
	Tms320c64xFunit funit;
	uint parallel;

    package this(in Capstone cs, cs_arch_detail arch_detail){
        auto internal = arch_detail.tms320c64x;
        foreach(op; internal.operands[0..internal.op_count])
            operands ~= Tms320c64xOp(cs, op);
		condition = Tms320c64xCondition(cs, internal.condition);
		funit = internal.funit.to!Tms320c64xFunit;
		parallel = internal.parallel;
    }
}

//=============================================================================
// Constants
//=============================================================================

/// Operand type for instruction's operands
enum Tms320c64xOpType {
	invalid = 0,  /// Uninitialized
	reg, 		  /// Register operand
	imm, 		  /// Immediate operand
	mem, 		  /// Memory operand
	regpair = 64, /// Register pair for double word ops
}

enum Tms320c64xMemDisp {
	invalid = 0,
	constant,
	register,
}

enum Tms320c64xMemDir {
	invalid = 0,
	fw,
	bw,
}

enum Tms320c64xMemMod {
	invalid = 0,
	no,
	pre,
	post,
}

enum Tms320c64xFunitType {
	invalid = 0,
	d,
	l,
	m,
	s,
	no
}

/// TMS320C64x registers
enum Tms320c64xRegisterId {
	invalid = 0,

	amr,
	csr,
	dier,
	dnum,
	ecr,
	gfpgfr,
	gplya,
	gplyb,
	icr,
	ier,
	ierr,
	ilc,
	irp,
	isr,
	istp,
	itsr,
	nrp,
	ntsr,
	rep,
	rilc,
	ssr,
	tsch,
	tscl,
	tsr,
	a0,
	a1,
	a2,
	a3,
	a4,
	a5,
	a6,
	a7,
	a8,
	a9,
	a10,
	a11,
	a12,
	a13,
	a14,
	a15,
	a16,
	a17,
	a18,
	a19,
	a20,
	a21,
	a22,
	a23,
	a24,
	a25,
	a26,
	a27,
	a28,
	a29,
	a30,
	a31,
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
	pce1,

	// Alias registers
	efr = ecr,
	ifr = isr,
}

/// TMS320C64x instructions
enum Tms320c64xInstructionId {
	invalid = 0,

	abs,
	abs2,
	add,
	add2,
	add4,
	addab,
	addad,
	addah,
	addaw,
	addk,
	addkpc,
	addu,
	and,
	andn,
	avg2,
	avgu4,
	b,
	bdec,
	bitc4,
	bnop,
	bpos,
	clr,
	cmpeq,
	cmpeq2,
	cmpeq4,
	cmpgt,
	cmpgt2,
	cmpgtu4,
	cmplt,
	cmpltu,
	deal,
	dotp2,
	dotpn2,
	dotpnrsu2,
	dotprsu2,
	dotpsu4,
	dotpu4,
	ext,
	extu,
	gmpgtu,
	gmpy4,
	ldb,
	ldbu,
	lddw,
	ldh,
	ldhu,
	ldndw,
	ldnw,
	ldw,
	lmbd,
	max2,
	maxu4,
	min2,
	minu4,
	mpy,
	mpy2,
	mpyh,
	mpyhi,
	mpyhir,
	mpyhl,
	mpyhlu,
	mpyhslu,
	mpyhsu,
	mpyhu,
	mpyhuls,
	mpyhus,
	mpylh,
	mpylhu,
	mpyli,
	mpylir,
	mpylshu,
	mpyluhs,
	mpysu,
	mpysu4,
	mpyu,
	mpyu4,
	mpyus,
	mvc,
	mvd,
	mvk,
	mvkl,
	mvklh,
	nop,
	norm,
	or,
	pack2,
	packh2,
	packh4,
	packhl2,
	packl4,
	packlh2,
	rotl,
	sadd,
	sadd2,
	saddu4,
	saddus2,
	sat,
	set,
	shfl,
	shl,
	shlmb,
	shr,
	shr2,
	shrmb,
	shru,
	shru2,
	smpy,
	smpy2,
	smpyh,
	smpyhl,
	smpylh,
	spack2,
	spacku4,
	sshl,
	sshvl,
	sshvr,
	ssub,
	stb,
	stdw,
	sth,
	stndw,
	stnw,
	stw,
	sub,
	sub2,
	sub4,
	subab,
	subabs4,
	subah,
	subaw,
	subc,
	subu,
	swap4,
	unpkhu4,
	unpklu4,
	xor,
	xpnd2,
	xpnd4,
	// Aliases
	idle,
	mv,
	neg,
	not,
	swap2,
	zero,
}

/// Group of TMS320C64x instructions
enum Tms320c64xInstructionGroupId {
	invalid = 0,

	jump,

	funit_d = 128,
	funit_l,
	funit_m,
	funit_s,
	funit_no,
}