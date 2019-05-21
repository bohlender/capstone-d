/// Range-based iteration over disassembled instructions
module capstone.range;

import std.exception: enforce, assertThrown;
import std.range: isInputRange;
import std.format: format;

import capstone.api;
import capstone.capstone;
import capstone.internal;
import capstone.instruction;
import capstone.error;

/// An extended `InstructionRange` that provides architecture-specific instructions
class InstructionImplRange(TInstruction) : InstructionRange {
    import core.exception: RangeError;
    private{
        const Capstone cs;
        const ubyte[] code; // Keep ref, s.t. it cannot be deallocated externally
        const(ubyte)* pCode;
        ulong codeLength;
        ulong address;

        TInstruction instr;
        cs_insn* pInsn;

        bool hasFront;
    }

    package this(in Capstone cs, in ubyte[] code, in ulong address){
        this.cs = cs;
        this.code = code;
        this.pCode = code.ptr;
        this.codeLength = code.length;
        this.address = address;
        this.hasFront = true;

        popFront;
    }

    /// True if no disassemblable instructions remain
    override bool empty() const {return !hasFront;}

    /** The latest disassembled instruction

    Throws if called on an `empty` range.
    */
    override TInstruction front() {
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
            instr = new TInstruction(cs, pInsn); // Instruction takes ownership of pointer
        else
            cs_errno(cs.handle).checkErrno;
    }
}
static assert(isInputRange!(InstructionRange));