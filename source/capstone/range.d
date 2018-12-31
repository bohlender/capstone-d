/// Range-based iteration over disassembled instructions
module capstone.range;

import std.exception: enforce, assertThrown;
import std.range: isInputRange;
import std.format: format;

import capstone.api: Arch, InstructionRange;
import capstone.impl: CapstoneImpl, InstructionImpl;
import capstone.internal;
import capstone.error;

/// An extended `InstructionRange` that provides architecture-specific instructions
class InstructionImplRange(Arch arch) : InstructionRange {
    import core.exception: RangeError;
    private{
        CapstoneImpl!arch cs;
        const ubyte[] code; // Keep ref, s.t. it cannot be deallocated externally
        const(ubyte)* pCode;
        ulong codeLength;
        ulong address;

        InstructionImpl!arch instr;
        cs_insn* pInsn;

        bool hasFront;
    }

    package this(CapstoneImpl!arch cs, in ubyte[] code, in ulong address){
        this.cs = cs;
        this.code = code;
        this.pCode = code.ptr;
        this.codeLength = code.length;
        this.address = address;
        this.hasFront = true;

        popFront;
    }

    /// True if no disassemblable instructions remain
    @property override bool empty() const {return !hasFront;}

    /** The latest disassembled instruction

    Throws if called on an `empty` range.
    */
    @property override InstructionImpl!arch front() {
        enforce!RangeError(!empty, "Trying to access an empty range (%s)".format(typeof(this).stringof));
        return instr;
    }

    /** Advances the range, disassembling the next instruction

    Throws if called on an `empty` range.
    */
    override void popFront(){
        enforce!RangeError(!empty, "Trying to access an empty range (%s)".format(typeof(this).stringof));
        pInsn = cs_malloc(cs.handle); // Is freed by Instruction
        if(!pInsn)
            throw new CapstoneException("Insufficient memory to allocate an instruction", ErrorCode.OutOfMemory);
        hasFront = cs_disasm_iter(cs.handle, &pCode, &codeLength, &address, pInsn);
        if(hasFront)
            instr = new InstructionImpl!arch(pInsn, cs.detail, cs.skipData); // Instruction takes ownership of pointer
        else
            cs_errno(cs.handle).checkErrno;
    }
}
static assert(isInputRange!(InstructionRange));