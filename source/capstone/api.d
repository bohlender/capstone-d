/**
 Idiomatic lifting of $(LINK2 http://www.capstone-engine.org, Capstone)'s C API to D
*/
module capstone.api;

import std.typecons: Tuple, BitFlags, Yes, Nullable;
import std.exception: enforce;
import std.format;
import std.conv;
import std.string;
import std.array;

import capstone.internal.api;
import source.capstone.error;
import capstone;

/// Architecture type
enum Arch{
    arm = 0, /// ARM architecture (including Thumb, Thumb-2)
    arm64,   /// ARM-64 (also called AArch64)
    mips,    /// Mips architecture
    x86,     /// X86 architecture (including x86 & x86-64)
    powerPc, /// Support for PowerPC architecture
    sparc,   /// Support for Sparc architecture
    systemZ, /// Support for SystemZ architecture
    xCore    /// Support for XCore architecture
}

/// The options that $(LINK2 http://www.capstone-engine.org, capstone) can have been compiled with to support
enum SupportQuery {
    arm = 0,      /// Support for ARM architecture (including Thumb, Thumb-2)
    arm64,        /// Support for ARM-64 (also called AArch64)
    mips,         /// Support for Mips architecture
    x86,          /// Support for X86 architecture (including x86 & x86-64)
    powerPc,      /// Support for PowerPC architecture
    sparc,        /// Support for Sparc architecture
    systemZ,      /// Support for SystemZ architecture
    xCore,        /// Support for XCore architecture
    all = 0xFFFF, /// Supports all architectures
    diet,         /// Compiled in diet mode, i.e. missing less relevant data fields
    x86Reduce     /// Compiled in X86-reduce mode, i.e. missing less relevant data fields and exotic X86 instruction sets
}

/// Mode type
enum Mode {
    littleEndian = 0,   /// Little-endian mode (default mode)
    arm = 0,            /// 32-bit ARM
    bit16 = 1 << 1,     /// 16-bit mode (X86)
    bit32 = 1 << 2,     /// 32-bit mode (X86)
    bit64 = 1 << 3,     /// 64-bit mode (X86, PPC)
    armThumb = 1 << 4,  /// ARM's Thumb mode, including Thumb-2
    armCortexM = 1 << 5,/// ARM's Cortex-M series
    armV8 = 1 << 6,     /// ARMv8 A32 encodings for ARM
    mipsMicro = 1 << 4, /// MicroMips mode (MIPS)
    mips3 = 1 << 5,     /// Mips III ISA
    mips32r6 = 1 << 6,  /// Mips32r6 ISA
    mipsGp64 = 1 << 7,  /// General Purpose Registers are 64-bit wide (MIPS)
    bigEndian = 1 << 31,/// SparcV9 mode (Sparc)
    sparcV9 = 1 << 4,   /// Big-endian mode
    mips32 = bit32,     /// Mips32 ISA (Mips)
    mips64 = bit64      /// Mips64 ISA (Mips)
}
/// Type for combination of several modes
alias ModeFlags = BitFlags!(Mode, Yes.unsafe);

/// Disassembly syntax variants
enum Syntax {
	systemDefault = 0, /// Default asm syntax
	intel,             /// X86 Intel asm syntax - default on X86
	att,               /// X86 ATT asm syntax
	noregname          /// Prints register name with only number
}

/// Architecture-independent instruction details
struct Detail(Arch arch) {
	Reg!arch[] regsRead;  /// Registers implicitly read by this instruction
	Reg!arch[] regsWrite; /// Registers implicitly modified by this instruction
	Group!arch[] groups;  /// Groups this instruction belongs to

	/// Architecture-specific instruction details
    InstructionDetail!arch archSpecific;
    /// Convenience-alias making `archSpecific`'s members directly accessible from this
    alias archSpecific this;

    private this(cs_detail internal){
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

/// Detail information of disassembled instruction
struct Instruction(Arch arch) {
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
	Id!arch id;
    
    /// Address (EIP) of this instruction
	ulong address;

	/// Machine bytes of this instruction
	ubyte[] bytes;

	/// Ascii text of instruction mnemonic
	string mnemonic;

	/// Ascii text of instruction operands
	string opStr;

	// NOTE: Instruction details only valid when both requirements below are met:
	// (1) CS_OP_DETAIL = CS_OPT_ON
	// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
	private Nullable!(Detail!arch) _detail;

    private this(cs_insn internal, bool detail, bool skipData){
        id = internal.id.to!(Id!arch); // TODO: throw
        address = internal.address;
        bytes = internal.bytes[0..internal.size].dup;
        mnemonic = internal.mnemonic.ptr.to!string;
        opStr = internal.op_str.ptr.to!string;

        if(detail && !skipData)
            _detail = Detail!arch(*internal.detail);
    }

    /** More details about the instruction

       Note that this is only available if both requirements are met: 
       $(OL $(LI details are enabled)
            $(LI the engine is not in Skipdata mode)
        )
    */ 
    @property detail() const {
        // TODO: Proper error
        enforce(!_detail.isNull, "Trying to acces unavailable instruction detail");
        return _detail;
    }
}

/** User-defined callback function type for SKIPDATA mode of operation
 
The first parameter is the input buffer containing code to be disassembled,
while the second one holds the position of the currently-examined byte in this buffer.

 Example:
 ---
 size_t callback(in ubyte[] code, size_t offset) {
     return 2;
 }
 ---
 See test/skipdata.d for full sample code demonstrating this API.

 Returns: The number of bytes to skip, or 0 to immediately stop disassembling
*/
alias Callback = size_t delegate(in ubyte[] code, size_t offset) nothrow @nogc;

// This trampoline is the ugly c-lang callback (calling d in turn)
private extern(C) size_t cCallback(const(ubyte)* code, size_t code_size, size_t offset, void* userData) nothrow @nogc{
    auto slice = code[0..code_size];
    
    // Call the nice d-lang callback
    auto dCallback = *cast(Callback*)userData;
    auto res = dCallback(slice, offset);
    return res;
}

// TODO: Replace by Tuple!(int, int)?
/// Version consisting of major and minor numbers
struct Version{
    int major; /// Major version number
    int minor; /// Minor version number

    /// Textual representation
    string toString() const {
        return "%s.%s".format(major, minor);
    }
}

private alias Handle = size_t;

/** Encapsulates an instance of the Capstone dissassembly engine

 Params:
    arch = The CPU architecture that the engine will assume when disassembling the byte-stream
*/
class Capstone(Arch arch){
    // TODO: Make static?
    /// Indicates whether the installed library was compiled in diet mode
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

    /** Constructs an instance of the disassembly engine

     Params:
        modeFlags = A combination of flags to further specify how bytes
                    will be interpreted, e.g. in little-endian.
    */
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

    /// Gets the mode of interpretation
    @property auto mode() const {return _mode;}
    /// Sets the mode of interpretation
    @property void mode(in ModeFlags modeFlags){
        _mode = modeFlags;
        // TODO: Handle error properly
        cs_option(handle, cs_opt_type.CS_OPT_MODE, modeFlags.to!uint).checkErrorCode;
    }

    /// Gets the disassembly syntax variant
    @property auto syntax() const {return _syntax;}
    /// Sets the disassembly syntax variant
    @property void syntax(in Syntax option){
        _syntax = option;
        // TODO: Handle error properly
        cs_option(handle, cs_opt_type.CS_OPT_SYNTAX, option).checkErrorCode;
    }

    /// Indicates whether the engine should disassemble instruction details
    @property auto detail() const {return _detail;}
    /// Sets whether the engine should disassemble instruction details
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

// TODO: Find a more elegant way.
// Get rid of these auxiliary templates here and in structs, e.g. Detail
private{
    template Id(Arch arch){
        static if(arch == Arch.arm)
            alias Id = ArmInstructionId;
        else static if(arch == Arch.arm64)
            alias Id = Arm64InstructionId;
        else static if(arch == Arch.x86)
            alias Id = X86InstructionId;
        else static assert(false);
    }

    template Reg(Arch arch){
        static if(arch == Arch.arm)
            alias Reg = ArmRegister;
        else static if(arch == Arch.arm64)
            alias Reg = Arm64Register;
        else static if(arch == Arch.x86)
            alias Reg = X86Register;
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
}