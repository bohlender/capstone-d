/// Types and constants of XCore architecture
module capstone.xcore;

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
class XCoreRegister : RegisterImpl!XCoreRegisterId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific InstructionGroup variant
class XCoreInstructionGroup : InstructionGroupImpl!XCoreInstructionGroupId {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }
}

/// Architecture-specific Detail variant
class XCoreDetail : DetailImpl!(XCoreRegister, XCoreInstructionGroup, XCoreInstructionDetail) {
    package this(in Capstone cs, cs_detail* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific instruction variant
class XCoreInstruction : InstructionImpl!(XCoreInstructionId, XCoreRegister, XCoreDetail) {
    package this(in Capstone cs, cs_insn* internal) {
		super(cs, internal);
	}
}

/// Architecture-specific Capstone variant
class CapstoneXCore : CapstoneImpl!(XCoreInstructionId, XCoreInstruction) {
    /** Creates an architecture-specific instance with a given mode of interpretation
    
    Params:
        modeFlags = The (initial) mode of interpretation, which can still be changed later on
    */
	this(in ModeFlags modeFlags){
        super(Arch.xcore, modeFlags);
    }
}

/** Instruction's operand referring to memory

This is associated with the `XCoreOpType.mem` operand type
*/
struct XCoreOpMem {
	XCoreRegister base;	 /// Base register
	XCoreRegister index; /// Index register
	int disp;			 /// Displacement/offset value
	int direct;			 /// +1: forward, -1: backward

	package this(in Capstone cs, xcore_op_mem internal){
		base = new XCoreRegister(cs, internal.base);
		index = new XCoreRegister(cs, internal.index);
		disp = internal.disp;
		direct = internal.direct;
	}
}

/// Union of possible operand types
union XCoreOpValue {
	XCoreRegister reg;	/// Register
	long imm;			/// Immediate
	XCoreOpMem mem;		/// Memory
}

/// Instruction's operand
struct XCoreOp {
    XCoreOpType type;   /// Operand type
    SafeUnion!XCoreOpValue value; /// Operand value of type `type`
    alias value this;   /// Convenient access to value (as in original bindings)

    package this(in Capstone cs, cs_xcore_op internal){
        type = internal.type.to!XCoreOpType;
        final switch(internal.type) {
            case XCoreOpType.invalid:
                break;
            case XCoreOpType.reg:
                value.reg = new XCoreRegister(cs, internal.reg);
                break;
            case XCoreOpType.imm:
                value.imm = internal.imm;
                break;
            case XCoreOpType.mem:
                value.mem = XCoreOpMem(cs, internal.mem);
                break;
        }
    }
}

/// XCore-specific information about an instruction
struct XCoreInstructionDetail {
    XCoreOp[] operands;          /// Operands for this instruction.

    package this(in Capstone cs, cs_arch_detail arch_detail){
		auto internal = arch_detail.xcore;
        foreach(op; internal.operands[0..internal.op_count])
            operands ~= XCoreOp(cs, op);
    }
}

//=============================================================================
// Constants
//=============================================================================

/// Operand type for instruction's operands
enum XCoreOpType {
	invalid = 0, /// Uninitialized
	reg, 		 /// Register operand
	imm, 		 /// Immediate operand
	mem, 		 /// Memory operand
}

/// XCore registers
enum XCoreRegisterId {
	invalid = 0,

	cp,
	dp,
	lr,
	sp,
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

	// Pseudo registers
	pc,	/// Program counter

	// Internal thread registers
	// See The-XMOS-XS1-Architecture(X7879A).pdf
	scp, /// Save pc
	ssr, /// Save status
	et,	 /// Exception type
	ed,	 /// Exception data
	sed, /// Save exception data
	kep, /// Kernel entry pointer
	ksp, /// Kernel stack pointer
	id,	 /// Thread ID
}

/// XCore instruction
enum XCoreInstructionId {
	invalid = 0,

	add,
	andnot,
	and,
	ashr,
	bau,
	bitrev,
	bla,
	blat,
	bl,
	bf,
	bt,
	bu,
	bru,
	byterev,
	chkct,
	clre,
	clrpt,
	clrsr,
	clz,
	crc8,
	crc32,
	dcall,
	dentsp,
	dgetreg,
	divs,
	divu,
	drestsp,
	dret,
	ecallf,
	ecallt,
	edu,
	eef,
	eet,
	eeu,
	endin,
	entsp,
	eq,
	extdp,
	extsp,
	freer,
	freet,
	getd,
	get,
	getn,
	getr,
	getsr,
	getst,
	getts,
	inct,
	init,
	inpw,
	inshr,
	int_,
	in_,
	kcall,
	kentsp,
	krestsp,
	kret,
	ladd,
	ld16s,
	ld8u,
	lda16,
	ldap,
	ldaw,
	ldc,
	ldw,
	ldivu,
	lmul,
	lss,
	lsub,
	lsu,
	maccs,
	maccu,
	mjoin,
	mkmsk,
	msync,
	mul,
	neg,
	not,
	or,
	outct,
	outpw,
	outshr,
	outt,
	out_,
	peek,
	rems,
	remu,
	retsp,
	setclk,
	set,
	setc,
	setd,
	setev,
	setn,
	setpsc,
	setpt,
	setrdy,
	setsr,
	settw,
	setv,
	sext,
	shl,
	shr,
	ssync,
	st16,
	st8,
	stw,
	sub,
	syncr,
	testct,
	testlcl,
	testwct,
	tsetmr,
	start,
	waitef,
	waitet,
	waiteu,
	xor,
	zext,
}

/// Group of XCore instructions
enum XCoreInstructionGroupId {
	invalid = 0,

	// Generic groups
	// All jump instructions (conditional+direct+indirect jumps)
	jump,
}