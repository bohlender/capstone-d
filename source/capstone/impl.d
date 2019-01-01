/// Extended API functionality for when the architecture is known at compile-time
module capstone.impl;

import std.typecons: Tuple, BitFlags, Yes, Nullable;
import std.exception: enforce, assertThrown;
import std.format: format;
import std.conv: to;
import std.array: array, appender;
import std.range: isInputRange, enumerate, front;
import std.algorithm: canFind;
import std.traits: EnumMembers;

import capstone.api;
import capstone.error;
import capstone.internal;
import capstone.range;

import capstone.arm;
import capstone.arm64;
import capstone.mips;
import capstone.ppc;
import capstone.sparc;
import capstone.sysz;
import capstone.x86;
import capstone.xcore;

// Auxiliary templates to derive the types to use as InstructionId, Register, InstructionGroup and InstructionDetail for a given architecture
private{
    import std.meta: AliasSeq;
    template ArchSpec(Arch arch){
        static if(arch == Arch.arm)
            alias ArchSpec = AliasSeq!(ArmInstructionId, ArmRegister, ArmInstructionGroup, ArmInstructionDetail);
        else static if(arch == Arch.arm64)
            alias ArchSpec = AliasSeq!(Arm64InstructionId, Arm64Register, Arm64InstructionGroup, Arm64InstructionDetail);
        else static if(arch == Arch.mips)
            alias ArchSpec = AliasSeq!(MipsInstructionId, MipsRegister, MipsInstructionGroup, MipsInstructionDetail);
        else static if(arch == Arch.ppc)
            alias ArchSpec = AliasSeq!(PpcInstructionId, PpcRegister, PpcInstructionGroup, PpcInstructionDetail);
        else static if(arch == Arch.sparc)
            alias ArchSpec = AliasSeq!(SparcInstructionId, SparcRegister, SparcInstructionGroup, SparcInstructionDetail);
        else static if(arch == Arch.sysz)
            alias ArchSpec = AliasSeq!(SyszInstructionId, SyszRegister, SyszInstructionGroup, SyszInstructionDetail);
        else static if(arch == Arch.x86)
            alias ArchSpec = AliasSeq!(X86InstructionId, X86Register, X86InstructionGroup, X86InstructionDetail);
        else static if(arch == Arch.xcore)
            alias ArchSpec = AliasSeq!(XCoreInstructionId, XCoreRegister, XCoreInstructionGroup, XCoreInstructionDetail);
        else static assert(false);
    }
    alias InstructionId(Arch arch) = ArchSpec!(arch)[0];
    alias Register(Arch arch) = ArchSpec!(arch)[1];
    alias InstructionGroup(Arch arch) = ArchSpec!(arch)[2];
    alias InstructionDetail(Arch arch) = ArchSpec!(arch)[3];
}

/// Instruction detail 
struct Detail(Arch arch) {
	Register!arch[] regsRead;       /// Registers implicitly read by this instruction
	Register!arch[] regsWrite;      /// Registers implicitly modified by this instruction
	InstructionGroup!arch[] groups; /// The groups this instruction belongs to

	/// Architecture-specific instruction detail
    InstructionDetail!arch archSpecific;
    /// Convenience-alias making `archSpecific`'s members directly accessible from this
    alias archSpecific this;

    private this(cs_detail internal){
        regsRead = internal.regs_read[0..internal.regs_read_count].to!(Register!arch[]);
        regsWrite = internal.regs_write[0..internal.regs_write_count].to!(Register!arch[]);
        groups = internal.groups[0..internal.groups_count].to!(InstructionGroup!arch[]);
        archSpecific = InstructionDetail!arch(internal.arch_detail);
    }
}

/// Architecture-specific instruction
class InstructionImpl(Arch arch) : Instruction {
	/// Instruction ID (basically a numeric ID for the instruction mnemonic)
    @property id() const {return internal.id.to!(InstructionId!arch);}

    private Nullable!(Detail!arch) _detail;

    package this(cs_insn* internal, bool detail, bool skipData){
        super(internal);
        if(detail && !skipData)
            _detail = Detail!arch(*internal.detail);
    }
    /** More details about the instruction
    
    Note that this is only available if both requirements are met: 
    $(OL
        $(LI details are enabled)
        $(LI the engine is not in Skipdata mode))
    */ 
    @property detail() const {
        if(_detail.isNull)
            throw new CapstoneException("Trying to access unavailable instruction detail", ErrorCode.UnavailableInstructionDetail);
        return _detail;
    }

    /** Checks whether the instruction belongs to the instruction group `group`

    Convenience method for searching through `detail.groups`.
    */
    bool isInGroup(InstructionGroup!arch group) const {
        return detail.groups.canFind(group);
    }

    /** Checks if the instruction IMPLICITLY uses a particular register

    Convenience method for searching through `detail.readRegs`.
    */
    bool readsReg(Register!arch reg) const {
        return detail.regsRead.canFind(reg);
    }

    /** Checks if the instruction IMPLICITLY modifies a particular register

    Convenience method for searching through `detail.writeRegs`.
    */
    bool writesReg(Register!arch reg) const {
        return detail.regsWrite.canFind(reg);
    }
}

/** Encapsulates an architecture-specific instance of the Capstone dissassembly engine

Note that, in contrast to the base class, the architecture is chosen at compile-time.

Params:
    archParam = The architecture this Capstone instance is tailored for
*/
class CapstoneImpl(Arch archParam) : Capstone { // Actually parametrised by Registers, InstructionId, InstructionDetail and InstructionGroup but those are uniquely implied by the architecture
    private string[InstructionId!archParam] customMnemonics;

    /** Creates an architecture-specific instance with a given mode of interpretation
    
    Params:
        modeFlags = The (initial) mode of interpretation, which can still be changed later on
    */
    this(in ModeFlags modeFlags){
        super(archParam, modeFlags);
    }

    override InstructionImpl!archParam[] disasm(in ubyte[] code, in ulong address, in size_t count = 0) const {
        auto instrAppnd = appender!(InstructionImpl!archParam[]);
        foreach(i, instr; disasmIter(code, address).enumerate){
            instrAppnd.put(instr);
            if(i+1==count)
                break;
        }
        return instrAppnd.data;
    }

    override InstructionImplRange!archParam disasmIter(in ubyte[] code, in ulong address) const {
        return new InstructionImplRange!archParam(this, code, address);
    }

    // TODO: Really needed? Almost identical to regular `toString`
    /** Determines friendly name of a register
    
    When in diet mode, this API is irrelevant because engine does not store register names
    Param:
        regId = Register id
    Returns: Friendly string representation of the register's name
    */
    string regName(Register!archParam regId) const {
        if(diet)
            throw new CapstoneException("Register names are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_reg_name(handle, regId).to!string;
    }

    // TODO: Really needed? Almost identical to regular `toString`
    /** Determines friendly name of an instruction
    
    When in diet mode, this API is irrelevant because engine does not store instruction names
    Param:
        instrId = Instruction id
    Returns: Friendly string representation of the instruction's name
    */
    string instrName(InstructionId!archParam instrId) const {
        if(diet)
            throw new CapstoneException("Instruction names are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_insn_name(handle, instrId).to!string;
    }

    // TODO: Really needed? Almost identical to regular `toString`
    /** Determines friendly name of a group id (that an instruction can belong to)
    
    When in diet mode, this API is irrelevant because engine does not store group names
    Param:
        groupId = Group id
    Returns: Friendly string representation of the group's name, or null if `groupId` is invalid
    */
    string groupName(InstructionGroup!archParam groupId) const {
        if(diet)
            throw new CapstoneException("Group names are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_group_name(handle, groupId).to!string;
    }

    /// Convenience-struct for accessing read & written registers
    static struct RegsAccess {
        Register!archParam[] read;
        Register!archParam[] write;
    }

    /// Retrieves both the implicitly and explicitly accessed registers
    auto regsAccess(in Instruction instr) const {
        if(diet)
            throw new CapstoneException("Registers accessed by an instruction are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        cs_regs read, write;
        ubyte numRead, numWrite;
        cs_regs_access(handle, instr.internal, &read, &numRead, &write, &numWrite).checkErrno;
        return RegsAccess(read[0..numRead].to!(Register!archParam[]), write[0..numWrite].to!(Register!archParam[]));
    }

    /** Defines a custom mnemonic for a specified instruction id

    */
    void customMnemonic(in InstructionId!archParam id, in string mnem = null) {
        auto optMnem = cs_opt_mnem(id, null);
        if(mnem != null){
            auto v = (customMnemonics[id] = mnem);
            optMnem.mnemonic = v.ptr;
        }else{
            customMnemonics.remove(id);
        }
        cs_option(handle, cs_opt_type.CS_OPT_MNEMONIC, cast(size_t)&optMnem).checkErrno;
    }
}

unittest{
    auto cs = new CapstoneImpl!(Arch.x86)(ModeFlags(Mode.bit32));
    assert(cs.regName(X86Register.eip) == "eip"); // Mostly same output as `to!string`
    assert(cs.regName(X86Register.st7) == "st(7)"); // Differs sometimes though

    assert(cs.instrName(X86InstructionId.add) == "add"); // Mostly same as `to!string`
    assert(cs.groupName(X86InstructionGroup.sse1) == "sse1"); // Mostly same as `to!string`
}

unittest{
    enum code = cast(ubyte[])"\x55";
    auto cs = new CapstoneImpl!(Arch.x86)(ModeFlags(Mode.bit64));
    cs.detail = true;

    auto range = cs.disasm(code, 0x1000);
    auto pushInstr = range.front;                            // 0x55 disassembles to "push"
    assert(pushInstr.mnemonic == "push");
    assert(pushInstr.isInGroup(X86InstructionGroup.mode64)); // "push" is part of the mode64 instructions
    assert(pushInstr.readsReg(X86Register.rsp));             // "push" accesses rsp
    assert(pushInstr.writesReg(X86Register.rsp));            // "push" modifies rsp
}