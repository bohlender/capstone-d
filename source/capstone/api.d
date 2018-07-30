module capstone.api;

import std.typecons: Tuple, BitFlags, Yes, Nullable;
import std.exception: enforce;
import std.format;
import std.conv;
import std.string;
import std.array;

// TODO: Remove
import std.stdio;

import capstone.internal.api;
import source.capstone.error;
import capstone;

enum Arch{
    arm = 0,
    arm64,
    mips,
    x86,
    powerPc,
    sparc,
    systemZ,
    xCore
}

enum SupportQuery {
    arm = 0,
    arm64,
    mips,
    x86,
    powerPc,
    sparc,
    systemZ,
    xCore,
    all = 0xFFFF,
    diet,
    x86Reduce
}

enum Mode {
    littleEndian = 0,
    arm = 0,
    bit16 = 1 << 1,
    bit32 = 1 << 2,
    bit64 = 1 << 3,
    armThumb = 1 << 4,
    armCortexM = 1 << 5,
    armV8 = 1 << 6,
    mipsMicro = 1 << 4,
    mips3 = 1 << 5,
    mips32r6 = 1 << 6,
    mipsGp64 = 1 << 7,
    bigEndian = 1 << 31,
    sparcV9 = 1 << 4,
    mips32 = bit32,
    mips64 = bit64
}
alias ModeFlags = BitFlags!(Mode, Yes.unsafe);

enum Syntax {
	systemDefault = 0, // Default asm syntax (CS_OPT_SYNTAX).
	intel, // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
	att,   // X86 ATT asm syntax (CS_OPT_SYNTAX).
	noregname // Prints register name with only number (CS_OPT_SYNTAX)
}

template Id(Arch arch){
    static if(arch == Arch.arm)
        alias ArmInstructionId Id;
    else static if(arch == Arch.arm64)
        alias Arm64InstructionId Id;
    else static if(arch == Arch.x86)
        alias X86InstructionId Id;
    else static assert(false);
}

template Reg(Arch arch){
    static if(arch == Arch.arm)
        alias ArmRegister Reg;
    else static if(arch == Arch.arm64)
        alias Arm64Register Reg;
    else static if(arch == Arch.x86)
        alias X86Register Reg;
    else static assert(false);
}

template Group(Arch arch){
    static if(arch == Arch.arm)
        alias ArmInstructionGroup Group;
    else static if(arch == Arch.arm64)
        alias Arm64InstructionGroup Group;
    else static if(arch == Arch.x86)
        alias X86InstructionGroup Group;
    else static assert(false);
}

template InstructionDetail(Arch arch){
    static if(arch == Arch.arm)
        alias ArmInstructionDetail InstructionDetail;
    else static if(arch == Arch.arm64)
        alias Arm64InstructionDetail InstructionDetail;
    else static if(arch == Arch.x86)
        alias X86InstructionDetail InstructionDetail;
    else static assert(false);
}

struct Detail(Arch arch) {
	Reg!arch[] regsRead; // list of implicit registers read by this insn
	Reg!arch[] regsWrite; // list of implicit registers modified by this insn
	Group!arch[] groups; // list of group this instruction belong to

	// Architecture-specific instruction info
    InstructionDetail!arch archSpecific;
    alias archSpecific this;

    this(cs_detail internal){
        regsRead = internal.regs_read[0..internal.regs_read_count].to!(Reg!arch[]);
        regsWrite = internal.regs_write[0..internal.regs_write_count].to!(Reg!arch[]);
        groups = internal.groups[0..internal.groups_count].to!(Group!arch[]);

        // TODO: Do properly
        static if(arch == Arch.arm)
            archSpecific = InstructionDetail!arch(internal.arm);
        else static if(arch == Arch.arm64)
            archSpecific = InstructionDetail!arch(internal.arm64);
        else static if(arch == Arch.x86)
            archSpecific = InstructionDetail!arch(internal.x86);
        else static assert(false);
    }
}

struct Instruction(Arch arch) {
	Id!arch id;
    
    // Address (EIP) of this instruction
	ulong address;

	// Machine bytes of this instruction, with number of bytes indicated by @size above
	ubyte[] bytes;

	// Ascii text of instruction mnemonic
	string mnemonic;

	// Ascii text of instruction operands
	string opStr;

    // Pointer to cs_detail.
	// NOTE: detail pointer is only valid when both requirements below are met:
	// (1) CS_OP_DETAIL = CS_OPT_ON
	// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
	//
	// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
	//     is not NULL, its content is still irrelevant.
	private Nullable!(Detail!arch) _detail;

    this(cs_insn internal, bool detail, bool skipData){
        id = internal.id.to!(Id!arch); // TODO: throw
        address = internal.address;
        bytes = internal.bytes[0..internal.size].dup;
        mnemonic = internal.mnemonic.ptr.to!string;
        opStr = internal.op_str.ptr.to!string;

        if(detail && !skipData)
            _detail = Detail!arch(*internal.detail);
    }

    @property const detail(){
        // TODO: Proper error
        enforce(!_detail.isNull);
        return _detail;
    }
}

alias Callback = size_t delegate(in ubyte[] code, size_t offset) nothrow @nogc;

// Trampoline is the ugly c-lang callback (calling d in turn)
extern(C) size_t cCallback(const(ubyte)* code, size_t code_size, size_t offset, void* userData) nothrow @nogc{
    auto slice = code[0..code_size];
    
    // Call the nice d-lang callback
    auto dCallback = *cast(Callback*)userData;
    auto res = dCallback(slice, offset);
    return res;
}

struct Version{
    int major, minor;

    string toString(){
        return "%s.%s".format(major, minor);
    }
}

alias Handle = size_t;

class Capstone(Arch arch){
    const bool diet;

    private{
        Handle handle;    
        
        ModeFlags _mode;
        Syntax _syntax;
        bool _detail;
        bool _skipData;

        string mnemonic;
        Callback callback;
    }

    this(in ModeFlags modeFlags){
        const libVer = versionOfLibrary;
        const bindVer = versionOfBindings;
        // TODO: Use custom exception ? Code: CS_ERR_VERSION
        enforce(libVer == bindVer, "API version mismatch between library (%d.%d) and bindings (%d.%d)"
            .format(libVer.major, libVer.minor, bindVer.major, bindVer.minor));

        this._mode = modeFlags;

        // TODO: Handle error properly
        cs_open(arch, modeFlags.to!uint, &handle).checkErrorCode;
        diet = cs_support(SupportQuery.diet);
    }

    ~this(){
        // TODO: Handle error properly
        cs_close(&handle).checkErrorCode;
    }

    @property auto mode() const {return _mode;}
    @property void mode(in ModeFlags modeFlags){
        _mode = modeFlags;
        // TODO: Handle error properly
        cs_option(handle, cs_opt_type.CS_OPT_MODE, modeFlags.to!uint).checkErrorCode;

    }

    @property auto syntax() const {return _syntax;}
    @property void syntax(in Syntax option){
        _syntax = option;
        // TODO: Handle error properly
        cs_option(handle, cs_opt_type.CS_OPT_SYNTAX, option).checkErrorCode;
    }

    @property auto detail() const {return _detail;}
    @property void detail(in bool enable){
        _detail = enable;
        // TODO: Handle error properly
        auto option = (enable ? cs_opt_value.CS_OPT_ON : cs_opt_value.CS_OPT_OFF);
        cs_option(handle, cs_opt_type.CS_OPT_DETAIL, option).checkErrorCode;
    }

    @property auto skipData() const {return _skipData;}
    @property void skipData(in bool enable){
        _skipData = enable;
        // TODO: Handle error properly
        auto option = (enable ? cs_opt_value.CS_OPT_ON : cs_opt_value.CS_OPT_OFF);
        cs_option(handle, cs_opt_type.CS_OPT_SKIPDATA, option).checkErrorCode;
    }

    void setupSkipdata(string mnemonic = ".byte", Callback callback = null){
        this.mnemonic = mnemonic;
        this.callback = callback;
        
        auto setup = cs_opt_skipdata(this.mnemonic.ptr, callback ? &cCallback : null, &this.callback);
        // TODO: Handle error properly
        cs_option(handle, cs_opt_type.CS_OPT_SKIPDATA_SETUP, cast(ulong)&setup).checkErrorCode;
    }

    auto disasm(in ubyte[] code, in ulong address, in size_t count = 0){
        cs_insn* internalInstrs;
        auto actualCount = cs_disasm(handle, code.ptr, code.length, address, count, &internalInstrs);
        scope(exit){cs_free(internalInstrs, actualCount);}

        auto instrAppnd = appender!(Instruction!arch[]);
        instrAppnd.reserve(actualCount);
        foreach(instr; internalInstrs[0..actualCount])
            instrAppnd.put(Instruction!arch(instr, detail, skipData));

        return instrAppnd.data;
    }

    string regName(Reg!arch regId) const {
        return cs_reg_name(handle, regId).to!string;
    }
}

auto versionOfBindings() {
    return Version(CS_API_MAJOR, CS_API_MINOR);
}
auto versionOfLibrary() {
    int major, minor;
    cs_version(&major, &minor);
    return Version(major, minor);
}

unittest{
    const libVer = versionOfLibrary;
    const bindVer = versionOfBindings;        
    assert(libVer == bindVer, "API version mismatch between library (%d.%d) and bindings (%d.%d)".format(libVer.major, libVer.minor, bindVer.major, bindVer.minor));
}

auto supports(in SupportQuery query){
    return cs_support(query);
}