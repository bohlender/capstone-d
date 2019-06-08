/// Object-oriented wrapper of Capstone disassembly engine
module capstone.capstone;

import std.typecons: Tuple, BitFlags, Yes, Nullable;
import std.format: format;
import std.conv: to;
import std.array: array, appender;
import std.range: isInputRange, enumerate, front;
import std.algorithm: canFind;
import std.traits: EnumMembers;

import capstone.api;
import capstone.instruction;
import capstone.internal;
import capstone.error;

/** Encapsulates an instance of the Capstone dissassembly engine

This class encapsulates the core functionality of the Capstone disassembly engine, providing
access to runtime options for
$(UL
    $(LI changing the `Mode` of interpretation)
    $(LI changing the `Syntax` of the disassembly)
    $(LI choosing whether `Instruction`'s should be disassembled in detail, i.e. filling `Instruction.detail`)
    $(LI defining manual handling of broken instructions through the $(LINK2 http://www.capstone-engine.org/skipdata.html, SKIPDATA) mode of operation (optionally via a `Callback`))
)

Note that, since the architecture is chosen at runtime, this base class only provides access to the architecture-indepentent aspects,
e.g. disasm returns `Instruction`s instead of `X86Instruction`s.
However, if necessary, it can be casted to the architecture-specific variant, such as `CapstoneX86`.
*/
abstract class Capstone{
    package {
        alias Handle = size_t;
        Handle handle;    
        
        ModeFlags _mode;
        Syntax _syntax;
        bool _detail;
        bool _skipData;

        string mnemonic;
        Callback callback;

        string[int] customMnemonics;
    }
    const Arch arch; /// The architecture this Capstone instance is set up for

    /** Constructs an instance of the disassembly engine

    Params:
        arch = The architecture the engine will be created for
        modeFlags = A combination of flags to further specify how bytes will be interpreted, e.g. in little-endian.
    */
    private this(in Arch arch, in ModeFlags modeFlags){
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

    /// Defines a custom mnemonic for a specified instruction id
    private void customMnemonic(in int id, in string mnem = null) {
        auto optMnem = cs_opt_mnem(id, null);
        if(mnem != null){
            const v = (customMnemonics[id] = mnem);
            optMnem.mnemonic = v.ptr;
        }else
            customMnemonics.remove(id);
        cs_option(handle, cs_opt_type.CS_OPT_MNEMONIC, cast(size_t)&optMnem).checkErrno;
    }

    /** Disassemble binary code, given the code buffer, start address and number of instructions to be decoded
    
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
    abstract const(Instruction)[] disasm(in ubyte[] code, in ulong address, in size_t count = 0) const;

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
    abstract InstructionRange disasmIter(in ubyte[] code, in ulong address) const;
}

// TODO: Try switching to InputRange!Instruction (more restrictive than isInputRange, though)
/// An input range that provides access to one disassembled `Instruction` at a time
abstract class InstructionRange {
    /// Retrieves element of the range
    Instruction front();
    /// True if range has no instructions, i.e. cannot be advanced anymore
    bool empty();
    /// Drops the front instruction and advances the range
    void popFront();
}
static assert(isInputRange!InstructionRange);

unittest{ // disasm
    auto CODE = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";
    auto cs = create(Arch.x86, ModeFlags(Mode.bit16));
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

/** Class template that encapsulates an architecture-specific instance of the Capstone dissassembly engine

Note that all architecture-specific instances, like `CapstoneX86`, instantiate and derive from this one.

Params:
    TInstructionId = The architecture-specific instruction identifier type
    TInstruction = The architecture-specific instruction type
*/
abstract class CapstoneImpl(TInstructionId, TInstruction) : Capstone {
    import capstone.range: InstructionImplRange;

    /** Creates an architecture-specific instance with a given mode of interpretation
    
    Params:
        arch = The architecture the engine will be created for
        modeFlags = The (initial) mode of interpretation, which can still be changed later on
    */
    package this(in Arch arch, in ModeFlags modeFlags){
        super(arch, modeFlags);
    }

    override TInstruction[] disasm(in ubyte[] code, in ulong address, in size_t count = 0) const {
        auto instrAppnd = appender!(TInstruction[]);
        foreach(i, instr; disasmIter(code, address).enumerate){
            instrAppnd.put(instr);
            if(i+1==count)
                break;
        }
        return instrAppnd.data;
    }

    override InstructionImplRange!TInstruction disasmIter(in ubyte[] code, in ulong address) const {
        return new InstructionImplRange!TInstruction(this, code, address);
    }

    /** Defines a custom mnemonic for a specified instruction id
    
    Example:
    ---
    enum X86_CODE32 = cast(ubyte[])"\x75\x01";
    auto cs = new CapstoneX86(ModeFlags(Mode.bit32));
    
    // Customize mnemonic JNE to JNZ
    cs.customMnemonic(X86InstructionId.jne, "jnz");
    
    foreach(instr; cs.disasm(X86_CODE32, 0x1000))
        writefln("%s\t%s", instr.mnemonic, instr.opStr);
    
    // Reset engine to use the default mnemonic of JNE
    cs.customMnemonic(X86InstructionId.jne);
    
    foreach(instr; cs.disasm(X86_CODE32, 0x1000))
        writefln("%s\t%s", instr.mnemonic, instr.opStr);
    ---
    */
    void customMnemonic(in TInstructionId id, in string mnem = null) {
        super.customMnemonic(id, mnem);
    }
}