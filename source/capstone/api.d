/// Idiomatic lifting of $(LINK2 http://www.capstone-engine.org, Capstone)'s C API to D
module capstone.api;

import std.typecons: BitFlags, Yes;

import capstone.internal;
import capstone.capstone: Capstone;

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
/** Alias for combination of several modes

Example:
---
auto flags = ModeFlags(Mode.arm + Mode.armV8);
---
*/
alias ModeFlags = BitFlags!(Mode, Yes.unsafe);


/// Disassembly syntax variants
enum Syntax {
	systemDefault = 0, /// System's default syntax
	intel,             /// X86 Intel syntax - default on X86
	att,               /// X86 AT&T syntax
	noregname,         /// Prints register name with only number
    masm,              /// X86 Intel Masm syntax
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
See `Capstone.setupSkipdata` documentation for full sample code demonstrating this functionality.
*/
alias Callback = size_t delegate(in ubyte[] code, size_t offset) nothrow @nogc;

// This trampoline is the ugly C-lang callback (calling D in turn)
package extern(C) size_t cCallback(const(ubyte)* code, size_t code_size, size_t offset, void* userData) nothrow @nogc{
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
        import std.format: format;
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
    import std.format: format;
    const libVer = versionOfLibrary;
    const bindVer = versionOfBindings;        
    assert(libVer == bindVer, "API version mismatch between library (%s) and bindings (%s)".format(libVer, bindVer));
}

/** Indicates whether the installed library was compiled in $(LINK2 http://www.capstone-engine.org/diet.html, diet mode)

Convenience functionality which is also available via `supports`.
*/
bool diet(){
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
bool supports(in SupportQuery query){
    return cs_support(query);
}

/// Common instruction operand access types - to be consistent across all architectures.
enum AccessType {
    invalid = 0,      /// Uninitialized/invalid access type.
	read    = 1 << 0, /// Operand read from memory or register.
	write   = 1 << 1, /// Operand write to memory or register.
}
/** Alias for combination of several flags

Example:
---
auto flags = AccessFlags(AccessType.read | AccessType.write);
---
*/
alias AccessFlags = BitFlags!AccessType;

// TODO: Rename to capstone?
/** Creates a Capstone instance for disassembling code of a specific architecture
Params:
    arch = The architecture to interpret the bytestream for
    modeFlags = The mode of interpretation

Example:
---
auto cs = create(Arch.x86, ModeFlags(Mode.bit32));
---
 */
static Capstone create(Arch arch, ModeFlags modeFlags){
    import std.format: format;
    import capstone.arm: CapstoneArm;
    import capstone.arm64: CapstoneArm64;
    import capstone.evm: CapstoneEvm;
    import capstone.m68k: CapstoneM68k;
    import capstone.m680x: CapstoneM680x;
    import capstone.mips: CapstoneMips;
    import capstone.ppc: CapstonePpc;
    import capstone.sparc: CapstoneSparc;
    import capstone.sysz: CapstoneSysz;
    import capstone.x86: CapstoneX86;
    import capstone.xcore: CapstoneXCore;
    import capstone.error: CapstoneException, ErrorCode;

    switch(arch){
        case Arch.arm: return new CapstoneArm(modeFlags);
        case Arch.arm64: return new CapstoneArm64(modeFlags);
        case Arch.evm: return new CapstoneEvm(modeFlags);
        case Arch.m68k: return new CapstoneM68k(modeFlags);
        case Arch.m680x: return new CapstoneM680x(modeFlags);
        case Arch.mips: return new CapstoneMips(modeFlags);
        case Arch.ppc: return new CapstonePpc(modeFlags);
        case Arch.sparc: return new CapstoneSparc(modeFlags);
        case Arch.sysz: return new CapstoneSysz(modeFlags);
        case Arch.x86: return new CapstoneX86(modeFlags);
        case Arch.xcore: return new CapstoneXCore(modeFlags);
        default:
            throw new CapstoneException("%s architecture not yet supported by bindings".format(arch), ErrorCode.UnsupportedArchitecture);
    }
}