/// Object-oriented wrapper of Capstone's instruction detail
module capstone.detail;

import capstone.capstone: Capstone;
import capstone.internal: cs_detail;
import capstone.register;
import capstone.instructiongroup;

/// Instruction detail 
abstract class Detail {
private:
    const Capstone cs;
    cs_detail* internal;

public:
    /// Registers implicitly read by this instruction
	const(Register)[] regsRead() const;
    /// Registers implicitly modified by this instruction
	const(Register)[] regsWrite() const;
    /// The groups this instruction belongs to
	const(InstructionGroup)[] groups() const;

    private this(in Capstone cs, cs_detail* internal){
        this.cs = cs;
        this.internal = internal;
    }
}

/** Class template that encapsulates architecture-specific instruction detail

Note that all architecture-specific instances, like `X86Detail`, instantiate and derive from this one.
*/
abstract class DetailImpl(TRegister, TInstructionGroup, TInstructionDetail) : Detail {
    import std.array: array;
    import std.algorithm: map;

    /// Architecture-specific instruction detail
    TInstructionDetail archSpecific;
    /// Convenience-alias making `archSpecific`'s members directly accessible from this
    alias archSpecific this;

    package this(in Capstone cs, cs_detail* internal){
        super(cs, internal);
        archSpecific = TInstructionDetail(cs, internal.arch_detail);
    }

	override TRegister[] regsRead() const {return internal.regs_read[0..internal.regs_read_count].map!(reg => new TRegister(cs, reg)).array;}
	override TRegister[] regsWrite() const {return internal.regs_write[0..internal.regs_write_count].map!(reg => new TRegister(cs, reg)).array;}
	override TInstructionGroup[] groups() const {return internal.groups[0..internal.groups_count].map!(grp => new TInstructionGroup(cs, grp)).array;}
}