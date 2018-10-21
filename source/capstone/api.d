/// Idiomatic lifting of $(LINK2 http://www.capstone-engine.org, Capstone)'s C API to D
module capstone.api;

import std.typecons: Tuple, BitFlags, Yes, Nullable;
import std.exception: enforce;
import std.format;
import std.conv;
import std.string;
import std.array;

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

/// The support options that Capstone can be compiled with
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
	systemDefault = 0, /// System's default syntax
	intel,             /// X86 Intel syntax - default on X86
	att,               /// X86 AT&T syntax
	noregname          /// Prints register name with only number
}

// Auxiliary templates to derive the types to use as InstructionId, Register, InstructionGroup and InstructionDetail for a given architecture
private{
    import std.meta: AliasSeq;
    template ArchSpec(Arch arch){
        static if(arch == Arch.arm)
            alias ArchSpec = AliasSeq!(ArmInstructionId, ArmRegister, ArmInstructionGroup, ArmInstructionDetail);
        else static if(arch == Arch.arm64)
            alias ArchSpec = AliasSeq!(Arm64InstructionId, Arm64Register, Arm64InstructionGroup, Arm64InstructionDetail);
        else static if(arch == Arch.x86)
            alias ArchSpec = AliasSeq!(X86InstructionId, X86Register, X86InstructionGroup, X86InstructionDetail);
        else static assert(false);
    }
    alias InstructionId(Arch arch) = ArchSpec!(arch)[0];
    alias Register(Arch arch) = ArchSpec!(arch)[1];
    alias InstructionGroup(Arch arch) = ArchSpec!(arch)[2];
    alias InstructionDetail(Arch arch) = ArchSpec!(arch)[3];
}

/// Architecture-independent instruction details
struct Detail(Arch arch) {
	Register!arch[] regsRead;       /// Registers implicitly read by this instruction
	Register!arch[] regsWrite;      /// Registers implicitly modified by this instruction
	InstructionGroup!arch[] groups; /// The groups this instruction belongs to

	/// Architecture-specific instruction details
    InstructionDetail!arch archSpecific;
    /// Convenience-alias making `archSpecific`'s members directly accessible from this
    alias archSpecific this;

    private this(cs_detail internal){
        regsRead = internal.regs_read[0..internal.regs_read_count].to!(Register!arch[]);
        regsWrite = internal.regs_write[0..internal.regs_write_count].to!(Register!arch[]);
        groups = internal.groups[0..internal.groups_count].to!(InstructionGroup!arch[]);

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
	InstructionId!arch id;
    
    /// Address (EIP) of this instruction
	ulong address;

	/// Machine bytes of this instruction
	ubyte[] bytes;

	/// Ascii text of instruction mnemonic
	string mnemonic;

	/// Ascii text of instruction operands
	string opStr;

	private Nullable!(Detail!arch) _detail;

    private this(cs_insn internal, bool detail, bool skipData){
        id = internal.id.to!(InstructionId!arch);
        address = internal.address;
        bytes = internal.bytes[0..internal.size].dup;
        mnemonic = internal.mnemonic.ptr.to!string;
        opStr = internal.op_str.ptr.to!string;

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
}

// TODO: Example for using custom data
// TODO: See test/skipdata.d for full sample code demonstrating this API.
/** User-defined callback function type for SKIPDATA mode of operation
 
The first parameter is the input buffer containing code to be disassembled,
while the second one holds the position of the currently-examined byte in this buffer.

Example:
---
size_t callback(in ubyte[] code, size_t offset) {
    return 2; // Always skip 2 bytes when encountering uninterpretable instructions
}
---

Returns: The number of bytes to skip, or 0 to immediately stop disassembling
*/
alias Callback = size_t delegate(in ubyte[] code, size_t offset) nothrow @nogc;

// This trampoline is the ugly c-lang callback (calling D in turn)
private extern(C) size_t cCallback(const(ubyte)* code, size_t code_size, size_t offset, void* userData) nothrow @nogc{
    auto slice = code[0..code_size];
    
    // Call the nice d-lang callback
    auto dCallback = *cast(Callback*)userData;
    auto res = dCallback(slice, offset);
    return res;
}

/// Version consisting of major and minor numbers
struct Version{
    int major; /// Major version number
    int minor; /// Minor version number

    /// Textual representation
    string toString() const {
        return "%s.%s".format(major, minor);
    }
}

/// Determines the `Version` supported by these bindings
auto versionOfBindings() {
    return Version(CS_API_MAJOR, CS_API_MINOR);
}

/// Determines the `Version` supported by the installed library
auto versionOfLibrary() {
    int major, minor;
    cs_version(&major, &minor);
    return Version(major, minor);
}

unittest{
    const libVer = versionOfLibrary;
    const bindVer = versionOfBindings;        
    assert(libVer == bindVer, "API version mismatch between library (%d.%d) and bindings (%d.%d)"
        .format(libVer.major, libVer.minor, bindVer.major, bindVer.minor));
}

/// Indicates whether the installed library was compiled in $(LINK2 http://www.capstone-engine.org/diet.html, diet mode)
auto diet(){
    return supports(SupportQuery.diet);
}

/** Indicates whether an architecture or particular option is supported by the installed Capstone library

Params:
    query = The `SupportQuery` to issue to the library
 
Returns: True if the requested option is supported
*/
auto supports(in SupportQuery query){
    return cs_support(query);
}

/** Encapsulates an instance of the Capstone dissassembly engine

This class encapsulates the core functionality of the Capstone disassembly engine, providing
access to runtime options for
$(UL
    $(LI changing the `Mode` of interpretation)
    $(LI changing the `Syntax` of the disassembly)
    $(LI choosing whether `Instruction`'s should be disassembled in detail, i.e. filling `Instruction.detail`)
    $(LI defining manual handling of broken instructions through the $(LINK2 http://www.capstone-engine.org/skipdata.html, SKIPDATA) mode of operation (optionally via a `Callback`))
)

Params:
    arch = The CPU architecture that the engine will disassemble the byte-stream for
*/
class Capstone(Arch arch){ // Actually parametrised by Registers, InstructionId, InstructionDetail and InstructionGroup but those are uniquely implied by the architecture
    private{
        alias Handle = size_t;
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
        modeFlags = A combination of flags to further specify how bytes will be interpreted, e.g. in little-endian.
    */
    this(in ModeFlags modeFlags){
        const libVer = versionOfLibrary;
        const bindVer = versionOfBindings;
        if(libVer != bindVer)
            throw new CapstoneException("API version mismatch between library (%d.%d) and bindings (%d.%d)"
                .format(libVer.major, libVer.minor, bindVer.major, bindVer.minor), ErrorCode.UnsupportedVersion);

        // Create Capstone engine instance
        this._mode = modeFlags;
        cs_open(arch, modeFlags.to!uint, &handle).checkErrno;

        // Sync members with library's default values
        // Note: not really necessary at the time of writing as they happen to match
        syntax = _syntax;
        detail = _detail;
        skipData = _skipData;
    }
    ///
    unittest{
        new Capstone!(Arch.x86)(ModeFlags(Mode.bit64));
    }

    ~this(){
        if(handle)
           cs_close(&handle).checkErrno;
    }

    /// Gets the mode of interpretation
    @property auto mode() const {return _mode;}
    /// Sets the mode of interpretation
    @property void mode(in ModeFlags modeFlags){
        _mode = modeFlags;
        cs_option(handle, cs_opt_type.CS_OPT_MODE, modeFlags.to!uint).checkErrno;
    }
    ///
    unittest{
        const code = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
        auto cs = new Capstone!(Arch.x86)(ModeFlags(Mode.bit16));
        cs.disasm(code, 0x1000);
        cs.mode = ModeFlags(Mode.bit32);
        cs.disasm(code, 0x1000);
    }

    /// Gets the disassembly syntax variant
    @property auto syntax() const {return _syntax;}
    /// Sets the disassembly syntax variant
    @property void syntax(in Syntax option){
        _syntax = option;
        cs_option(handle, cs_opt_type.CS_OPT_SYNTAX, option).checkErrno;
    }

    /// Indicates whether instructions will be disassembled in detail
    @property auto detail() const {return _detail;}
    /// Sets whether instructions will be disassembled in detail
    @property void detail(in bool enable){
        _detail = enable;
        auto option = (enable ? cs_opt_value.CS_OPT_ON : cs_opt_value.CS_OPT_OFF);
        cs_option(handle, cs_opt_type.CS_OPT_DETAIL, option).checkErrno;
    }

    /// Indicates whether SKIPDATA mode of operation is in use
    @property auto skipData() const {return _skipData;}
    /// Sets whether to use SKIPDATA mode of operation
    @property void skipData(in bool enable){
        _skipData = enable;
        auto option = (enable ? cs_opt_value.CS_OPT_ON : cs_opt_value.CS_OPT_OFF);
        cs_option(handle, cs_opt_type.CS_OPT_SKIPDATA, option).checkErrno;
    }

    /** Customises behaviour in SKIPDATA mode of operation
     
    By default, disassembling will stop when it encounters a broken instruction.
    Most of the time, the reason is that this is data mixed inside the input.

    When in SKIPDATA mode, some (unknown) amount of data until the next interpretable instruction will be skipped.
    Capstone considers the skipped data a special instruction with ID 0x00 and a `mnemonic` that defaults to `".byte"`.
    The operand string is a hex-code of the sequence of bytes it skipped.

    By default, for each iteration, Capstone skips 1 byte on X86 architecture, 2 bytes on Thumb mode on Arm
    architecture, and 4 bytes for the rest. The reason while Capstone skips 1 byte on X86 is that X86 puts no
    restriction on instruction alignment, but other architectures enforce some requirements on this aspect.

    To customise how many bytes to skip when encountering data, a `Callback` delegate can optonally be setup
    to return the corresponding number.

    Params:
        mnemonic = The mnemonic to use for representing skipped data
        callback = The optional callback to use for handling bytes that cannot be interpreted as an instruction.
    */
    void setupSkipdata(in string mnemonic = ".byte", Callback callback = null){
        if(!mnemonic)
            throw new CapstoneException("Invalid mnemonic", ErrorCode.InvalidOption);
        this.mnemonic = mnemonic;
        this.callback = callback;
        
        auto setup = cs_opt_skipdata(this.mnemonic.ptr, this.callback ? &cCallback : null, &this.callback);
        cs_option(handle, cs_opt_type.CS_OPT_SKIPDATA_SETUP, cast(ulong)&setup).checkErrno;
    }

    // TODO: for system with scarce memory to be dynamically allocated such as OS kernel or firmware, the API cs_disasm_iter() might be a better choice than cs_disasm()
    /** Disassemble binary code, given the code buffer, address and number of instructions to be decoded
    
    Params:
        code    = Buffer containing raw binary code to be disassembled
        address = Address of the first instruction in given raw code buffer
        count   = Number of instructions to be disassembled, or 0 to get all of them
    Returns: The successfully disassembled instructions
    */
    auto disasm(in ubyte[] code, in ulong address, in size_t count = 0){
        cs_insn* internalInstrs;
        auto actualCount = cs_disasm(handle, code.ptr, code.length, address, count, &internalInstrs);
        scope(exit){if(internalInstrs){cs_free(internalInstrs, actualCount);}}
        cs_errno(handle).checkErrno;

        auto instrAppnd = appender!(Instruction!arch[]);
        instrAppnd.reserve(actualCount);
        foreach(instr; internalInstrs[0..actualCount])
            instrAppnd.put(Instruction!arch(instr, detail, skipData));

        return instrAppnd.data;
    }

    /** Determines user-friendly name of a register
    
    When in diet mode, this API is irrelevant because engine does not store register names
    Param:
        regId = register id
    Returns: user-friendly string representation of the register's name
    */
    string regName(Register!arch regId) const {
        if(diet)
            throw new CapstoneException("Register names are not stored when running Capstone in diet mode", ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_reg_name(handle, regId).to!string;
    }
}