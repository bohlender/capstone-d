/// Idiomatic lifting of $(LINK2 http://www.capstone-engine.org, Capstone)'s C API to D
module capstone.api;

import std.typecons: Tuple, BitFlags, Yes, Nullable;
import std.format: format;
import std.conv: to;
import std.array: array, appender;
import std.range: isInputRange, enumerate, front;
import std.algorithm: canFind;
import std.traits: EnumMembers;

import capstone.internal;
import capstone.error;
import capstone.impl: CapstoneImpl;

/// Architecture type
enum Arch{
    arm = 0,    /// ARM architecture (including Thumb, Thumb-2)
    arm64,      /// ARM-64 (also called AArch64)
    mips,       /// Mips architecture
    x86,        /// X86 architecture (including x86 & x86-64)
    ppc,        /// PowerPC architecture
    sparc,      /// Sparc architecture
    sysz,       /// SystemZ architecture
    xcore,      /// XCore architecture
    m68k,		/// 68K architecture
    tms320c64x,	/// TMS320C64x architecture
    m680x,		/// 680X architecture
    evm,        /// Ethereum architecture
}

/// The support options that Capstone can be compiled with
enum SupportQuery {
    arm = 0,      /// Support for ARM architecture (including Thumb, Thumb-2)
    arm64,        /// Support for ARM-64 (also called AArch64)
    mips,         /// Support for Mips architecture
    x86,          /// Support for X86 architecture (including x86 & x86-64)
    ppc,          /// Support for PowerPC architecture
    sparc,        /// Support for Sparc architecture
    sysz,         /// Support for SystemZ architecture
    xcore,        /// Support for XCore architecture
    m68k,		  /// 68K architecture
    tms320c64x,	  /// TMS320C64x architecture
    m680x,		  /// 680X architecture
    evm,          /// Ethereum architecture
    all = 0xFFFF, /// Supports all architectures
    diet,         /// Compiled in diet mode, i.e. missing less relevant data fields
    x86reduce     /// Compiled in X86-reduce mode, i.e. missing less relevant data fields and exotic X86 instruction sets
}

/// Mode type
enum Mode {
    littleEndian = 0,      /// Little-endian mode (default mode)
    arm = 0,               /// 32-bit ARM
    bit16 = 1 << 1,        /// 16-bit mode (X86)
    bit32 = 1 << 2,        /// 32-bit mode (X86)
    bit64 = 1 << 3,        /// 64-bit mode (X86, PPC)
    armThumb = 1 << 4,     /// ARM's Thumb mode, including Thumb-2
    armCortexM = 1 << 5,   /// ARM's Cortex-M series
    armV8 = 1 << 6,        /// ARMv8 A32 encodings for ARM
    mipsMicro = 1 << 4,    /// MicroMips mode (MIPS)
    mips3 = 1 << 5,        /// Mips III ISA
    mips32r6 = 1 << 6,     /// Mips32r6 ISA
    mips2 = 1 << 7,        /// Mips II ISA
    sparcV9 = 1 << 4,      /// SparcV9 mode (Sparc)
	qpx = 1 << 4,          /// Quad Processing eXtensions mode (PPC)
    m68k_000 = 1 << 1,     /// M68K 68000 mode
	m68k_010 = 1 << 2,     /// M68K 68010 mode
	m68k_020 = 1 << 3,     /// M68K 68020 mode
	m68k_030 = 1 << 4,     /// M68K 68030 mode
	m68k_040 = 1 << 5,     /// M68K 68040 mode
    m68k_060 = 1 << 6,     /// M68K 68060 mode
    bigEndian = 1 << 31,   /// Big-endian mode
    mips32 = bit32,        /// Mips32 ISA (Mips)
    mips64 = bit64,        /// Mips64 ISA (Mips)
    m680x_6301 = 1 << 1,   /// M680X Hitachi 6301,6303 mode
    m680x_6309 = 1 << 2,   /// M680X Hitachi 6309 mode
    m680x_6800 = 1 << 3,   /// M680X Motorola 6800,6802 mode
    m680x_6801 = 1 << 4,   /// M680X Motorola 6801,6803 mode
    m680x_6805 = 1 << 5,   /// M680X Motorola/Freescale 6805 mode
    m680x_6808 = 1 << 6,   /// M680X Motorola/Freescale/NXP 68HC08 mode
    m680x_6809 = 1 << 7,   /// M680X Motorola 6809 mode
    m680x_6811 = 1 << 8,   /// M680X Motorola/Freescale/NXP 68HC11 mode
    m680x_cpu12 = 1 << 9,  /// M680X Motorola/Freescale/NXP CPU12
    m680x_hcs08 = 1 << 10, /// M680X Freescale/NXP HCS08 mode
}
/// Type for combination of several modes
alias ModeFlags = BitFlags!(Mode, Yes.unsafe);

/// Disassembly syntax variants
enum Syntax {
	systemDefault = 0, /// System's default syntax
	intel,             /// X86 Intel syntax - default on X86
	att,               /// X86 AT&T syntax
	noregname,         /// Prints register name with only number
    masm,              /// X86 Intel Masm syntax
}

/** Common instruction operand access types - to be consistent across all architectures.

It is possible to combine access types, for example: AccessFlags(AccessType.read | AccessType.write)
*/
enum AccessType {
    invalid = 0,      /// Uninitialized/invalid access type.
	read    = 1 << 0, /// Operand read from memory or register.
	write   = 1 << 1, /// Operand write to memory or register.
}
alias AccessFlags = BitFlags!AccessType;

/// Architecture-independent instruction
abstract class Instruction {
    // TODO: Make const & uniqueptr?
    package cs_insn* internal; // Have to keep it around for cs_regs_access

	/// Address (EIP) of this instruction
    @property address() const {return internal.address;}
	/// Machine bytes of this instruction
    @property bytes() const {return internal.bytes[0..internal.size];}
	/// Ascii text of instruction mnemonic
    @property mnemonic() const {return internal.mnemonic.ptr.to!string;}
	/// Ascii text of instruction operands
    @property opStr() const {return internal.op_str.ptr.to!string;}
	
    protected this(cs_insn* internal){
        this.internal = internal;
    }

    ~this(){
        assert(internal);
        cs_free(internal, 1);
    }
}

/** User-defined callback function type for SKIPDATA mode of operation
 
The first parameter is the input buffer containing code to be disassembled,
while the second one holds the position of the currently-examined byte in this buffer.

Returns: The number of bytes to skip, or 0 to immediately stop disassembling

Example:
---
size_t callback(in ubyte[] code, size_t offset) {
    return 2; // Always skip 2 bytes when encountering uninterpretable instructions
}
---
See `setupSkipdata` documentation for full sample code demonstrating this functionality.
*/
alias Callback = size_t delegate(in ubyte[] code, size_t offset) nothrow @nogc;

// This trampoline is the ugly C-lang callback (calling D in turn)
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
///
unittest{
    const libVer = versionOfLibrary;
    const bindVer = versionOfBindings;        
    assert(libVer == bindVer, "API version mismatch between library (%s) and bindings (%s)".format(libVer, bindVer));
}

/** Indicates whether the installed library was compiled in $(LINK2 http://www.capstone-engine.org/diet.html, diet mode)

Convenience functionality which is also available via `supports`.
*/
auto diet(){
    return supports(SupportQuery.diet);
}

/** Indicates whether an architecture or particular option is supported by the installed Capstone library

Params:
    query = The `SupportQuery` to issue to the library
 
Returns: True if the requested option is supported

Example:
---
// Query installed Capstone library for supported options
foreach(query; EnumMembers!SupportQuery)
    writefln!"%-10s: %s"(query, supports(query));
---
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

Note that, since the architecture is chosen at runtime, this base class only gives access to the architecture-indepentent aspects,
but can be cast to the `CapstoneImpl` of corresponding architecture.
*/
abstract class Capstone{
    package{
        alias Handle = size_t;
        Handle handle;    
        
        ModeFlags _mode;
        Syntax _syntax;
        bool _detail;
        bool _skipData;

        string mnemonic;
        Callback callback;
    }
    const Arch arch;

    /** Constructs an instance of the disassembly engine

    Params:
        modeFlags = A combination of flags to further specify how bytes will be interpreted, e.g. in little-endian.
    */
    package this(in Arch arch, in ModeFlags modeFlags){
        const libVer = versionOfLibrary;
        const bindVer = versionOfBindings;
        if(libVer != bindVer)
            throw new CapstoneException("API version mismatch between library (%s) and bindings (%s)".format(libVer, bindVer), ErrorCode.UnsupportedVersion);

        // Create Capstone engine instance
        this.arch = arch;
        this._mode = modeFlags;
        cs_open(arch, modeFlags.to!uint, &handle).checkErrno;
    }

    ~this(){
        if(handle)
           cs_close(&handle).checkErrno;
    }
    
    /** Creates a Capstone instance for disassembling code of a specific architecture

    Params:
        arch = The architecture to interpret the bytestream for
        modeFlags = The mode of interpretation
     */
    static Capstone create(Arch arch, ModeFlags modeFlags){
        switch(arch){
            case Arch.arm:
                return new CapstoneImpl!(Arch.arm)(modeFlags);
            case Arch.arm64:
                return new CapstoneImpl!(Arch.arm64)(modeFlags);
            case Arch.mips:
                return new CapstoneImpl!(Arch.mips)(modeFlags);
            case Arch.ppc:
                return new CapstoneImpl!(Arch.ppc)(modeFlags);
            case Arch.sparc:
                return new CapstoneImpl!(Arch.sparc)(modeFlags);
            case Arch.sysz:
                return new CapstoneImpl!(Arch.sysz)(modeFlags);
            case Arch.x86:
                return new CapstoneImpl!(Arch.x86)(modeFlags);
            case Arch.xcore:
                return new CapstoneImpl!(Arch.xcore)(modeFlags);
            default:
                throw new CapstoneException("%s architecture not supported yet".format(arch), ErrorCode.UnsupportedArchitecture);
        }
    }

    /// Gets the mode of interpretation
    @property auto mode() const {return _mode;}
    /// Sets the mode of interpretation
    @property void mode(in ModeFlags modeFlags){
        _mode = modeFlags;
        cs_option(handle, cs_opt_type.CS_OPT_MODE, modeFlags.to!uint).checkErrno;
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
        auto option = enable ? cs_opt_value.CS_OPT_ON : cs_opt_value.CS_OPT_OFF;
        cs_option(handle, cs_opt_type.CS_OPT_DETAIL, option).checkErrno;
    }

    /// Indicates whether SKIPDATA mode of operation is in use
    @property auto skipData() const {return _skipData;}
    /// Sets whether to use SKIPDATA mode of operation
    @property void skipData(in bool enable){
        _skipData = enable;
        auto option = enable ? cs_opt_value.CS_OPT_ON : cs_opt_value.CS_OPT_OFF;
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
    
    Example:
    ---
    // Custom data that can be referred to in a callback delegate
    struct CallbackData{
        int bytesToSkip;
    }
    auto myData = CallbackData(1);
    size_t myCallback(in ubyte[] code, size_t offset) {
        return myData.bytesToSkip++; // Always skip one more byte when encountering data
    }
    cs.skipData = true;                     // Enable skipdata mode
    cs.setupSkipdata("db", &myCallback);    // Use custom callback, and "db" as custom mnemonic for data
    ---
    */
    void setupSkipdata(in string mnemonic = ".byte", Callback callback = null){
        if(!mnemonic)
            throw new CapstoneException("Invalid mnemonic", ErrorCode.InvalidOption);
        this.mnemonic = mnemonic;
        this.callback = callback;
        
        auto setup = cs_opt_skipdata(this.mnemonic.ptr, this.callback ? &cCallback : null, &this.callback);
        cs_option(handle, cs_opt_type.CS_OPT_SKIPDATA_SETUP, cast(size_t)&setup).checkErrno;
    }

    // TODO: Update docstring (using disasmIter anyway now)
    /** Disassemble binary code, given the code buffer, start address and number of instructions to be decoded
    
    For systems with scarce memory, the API `disasmIter` might be a better choice than `disasm`
    Params:
        code    = Buffer containing raw binary code to be disassembled
        address = Address of the first instruction in given raw code buffer
        count   = Number of instructions to be disassembled, or 0 to get all of them
    Returns: The successfully disassembled instructions

    Example:
    ---
    auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
    auto cs = new CapstoneX86(ModeFlags(Mode.bit32)); // Initialise x86 32bit engine
    auto res = cs.disasm(CODE, 0x1000);               // Disassemble, offsetting addresses by 0x1000
    assert("%s %s".format(res[0].mnemonic, res[0].opStr) == "lea ecx, dword ptr [edx + esi + 8]");
    assert("%s %s".format(res[1].mnemonic, res[1].opStr) == "add eax, ebx");
    assert("%s %s".format(res[2].mnemonic, res[2].opStr) == "add esi, 0x1234");
    ---
    */
    abstract const(Instruction)[] disasm(in ubyte[] code, in ulong address, in size_t count = 0);

    /** Provides a range to iteratively disassemble binary code - one instruction at a time

    Fast API to disassemble binary code, given the code buffer and start address.
    Provides access to only one disassembled instruction at a time, resulting in a smaller memory footprint.
    Params:
        code    = Buffer containing raw binary code to be disassembled
        address = Address of the first instruction in given raw code buffer
    Returns: An input range over the disassembled instructions

    Example:
    ---
    auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";

    auto cs = new CapstoneX86(ModeFlags(Mode.bit32)); // Initialise x86 32bit engine
    auto range = cs.disasmIter(CODE, 0x1000);         // Disassemble one instruction at a time, offsetting addresses by 0x1000
    assert("%s %s".format(range.front.mnemonic, range.front.opStr) == "lea ecx, dword ptr [edx + esi + 8]");
    range.popFront;
    assert("%s %s".format(range.front.mnemonic, range.front.opStr) == "add eax, ebx");
    range.popFront;
    assert("%s %s".format(range.front.mnemonic, range.front.opStr) == "add esi, 0x1234");
    range.popFront;
    assert(range.empty);
    ---
    */
    abstract InstructionRange disasmIter(in ubyte[] code, in ulong address);
}

// TODO: Try switching to InputRange!Instruction (more restrictive than isInputRange, though)
/// An input range that provides access to one disassembled `Instruction` at a time
abstract class InstructionRange {
    @property Instruction front();
    @property bool empty();
    void popFront();
}
static assert(isInputRange!InstructionRange);

unittest{ // disasm
    auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
    auto cs = Capstone.create(Arch.x86, ModeFlags(Mode.bit16));
    cs.mode = ModeFlags(Mode.bit32);

    auto res = cs.disasm(CODE, 0x1000);
    assert(res.length == 3); // With skipdata disabled, disassembling will halt when encountering data
    assert("%s %s".format(res[0].mnemonic, res[0].opStr) == "lea ecx, [edx + esi + 8]");
    assert("%s %s".format(res[1].mnemonic, res[1].opStr) == "add eax, ebx");
    assert("%s %s".format(res[2].mnemonic, res[2].opStr) == "add esi, 0x1234");
    cs.skipData = true;
    res = cs.disasm(CODE, 0x1000, 5);
    assert(res.length == 5);
}

unittest{ // skipdata
    auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
    // Custom data that can be referred to in a callback delegate
    struct CallbackData{
        int bytesToSkip;
    }
    auto myData = CallbackData(1);
    size_t myCallback(in ubyte[] code, size_t offset) {
        return myData.bytesToSkip++; // Always skip one more byte when encountering data
    }
    auto cs = Capstone.create(Arch.x86, ModeFlags(Mode.bit32));
    cs.skipData = true;                     // Enable skipdata mode
    cs.setupSkipdata("db", &myCallback);    // Use custom callback, and "db" as custom mnemonic for data
    const instrs = cs.disasm(CODE, 0x1000); // Disassemble (offsetting addresses by 0x1000)
    assert(instrs.length == 6);
}

unittest{ // disasmIter
    auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
    auto cs = Capstone.create(Arch.x86, ModeFlags(Mode.bit32)); // Initialise x86 32bit engine
    auto range = cs.disasmIter(CODE, 0x1000);         // Disassemble one instruction at a time, offsetting addresses by 0x1000
    assert("%s %s".format(range.front.mnemonic, range.front.opStr) == "lea ecx, [edx + esi + 8]");
    range.popFront;
    assert("%s %s".format(range.front.mnemonic, range.front.opStr) == "add eax, ebx");
    range.popFront;
    assert("%s %s".format(range.front.mnemonic, range.front.opStr) == "add esi, 0x1234");
    range.popFront;
    assert(range.empty);

    // Once empty, both `front` and `popFront` cannot be accessed
    import std.exception: assertThrown;
    import core.exception: RangeError;
    assertThrown!RangeError(range.front);
    assertThrown!RangeError(range.popFront);

    cs.skipData = true;
    assert(cs.disasmIter(CODE, 0x1000).array.length == 6);
}