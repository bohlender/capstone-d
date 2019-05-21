/// Object-oriented wrapper of disassembled instructions
module capstone.instruction;

import std.conv: to;
import std.typecons: Nullable;
import std.algorithm: canFind;

import capstone.api;
import capstone.capstone;
import capstone.detail;
import capstone.error;
import capstone.internal;
import capstone.instructiongroup;
import capstone.register;

/// Architecture-independent instruction base class
abstract class Instruction {
private:
    const Capstone cs;
    cs_insn* internal; // Have to keep it around for cs_regs_access

public:
	/// Address (EIP) of this instruction
    auto address() const {return internal.address;}
	/// Machine bytes of this instruction
    auto bytes() const {return internal.bytes[0..internal.size];}
	/// Ascii text of instruction mnemonic
    auto mnemonic() const {return internal.mnemonic.ptr.to!string;}
	/// Ascii text of instruction operands
    auto opStr() const {return internal.op_str.ptr.to!string;}
	
    private this(in Capstone cs, cs_insn* internal){
        this.cs = cs;
        this.internal = internal;
    }

    ~this(){
        assert(internal);
        cs_free(internal, 1);
    }

    /// Retrieves instruction's id as plain integer
    auto idAsInt() const {return internal.id;}

    /** Returns friendly string representation of an instruction's name
    
    When in diet mode, this API is irrelevant because engine does not store instruction names.
    */
    string name() const {
        if(diet)
            throw new CapstoneException("Instruction names are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_insn_name(cs.handle, internal.id).to!string; // TODO: Error handling
    }

    /** More details about the instruction
    
    Note that this is only available if both requirements are met: 
    $(OL
        $(LI details are enabled)
        $(LI the engine is not in Skipdata mode))
    */ 
    const(Detail) detail() const;

    /// Checks whether the instruction belongs to the instruction group `group`
    bool isInGroup(in InstructionGroup group) const {
        return cs_insn_group(cs.handle, internal, group._id); // TODO: Error handling
    }

    /// Checks if the instruction IMPLICITLY uses a particular register
    bool reads(in Register reg) const {
        return cs_reg_read(cs.handle, internal, reg._id); // TODO: Error handling
    }

    /// Checks if the instruction IMPLICITLY modifies a particular register
    bool writes(in Register reg) const {
        return cs_reg_write(cs.handle, internal, reg._id); // TODO: Error handling
    }

    /// Retrieves both the implicitly and explicitly written registers
    const(Register)[] writes() const;

    /// Retrieves both the implicitly and explicitly read registers
    const(Register)[] reads() const;
}

/** Class template for architecture-specific instructions

Note that all architecture-specific instances, like `X86Instruction`, instantiate and derive from this one.
*/
abstract class InstructionImpl(TId, TRegister, TDetail) : Instruction if(is(TId == enum)) { // TODO: isRegister, isDetail
    private Nullable!TDetail _detail;

    package this(in Capstone cs, cs_insn* internal){
        super(cs, internal);
        if(cs.detail && !cs.skipData)
            _detail = new TDetail(cs, internal.detail);
    }

	/// Retrieves instruction's id
    auto id() const {return internal.id.to!TId;}

    override const(TDetail) detail() const {
        if(_detail.isNull)
            throw new CapstoneException("Trying to access unavailable instruction detail", ErrorCode.UnavailableInstructionDetail);
        return _detail.get;
    }

    private const(TRegister)[] accessedRegs(in bool writeAccess) const {
        import std.algorithm: map;
        import std.array: array;

        if(diet)
            throw new CapstoneException("Registers accessed by an instruction are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        cs_regs read, write;
        ubyte numRead, numWrite;
        cs_regs_access(cs.handle, internal, &read, &numRead, &write, &numWrite).checkErrno;
        auto regs = writeAccess ? write[0..numWrite] : read[0..numRead];
        return regs.map!(reg => new TRegister(cs, reg)).array;
    }

    override const(TRegister)[] writes() const {return accessedRegs(true);}
    override const(TRegister)[] reads() const {return accessedRegs(false);}
}