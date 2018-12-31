module test.error;

import std.exception: collectException;

import capstone;

// TODO: Implement and provoke UninitializedDynamicMemoryManagement,

enum X86_CODE32 = cast(ubyte[])"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92";

unittest{
	{// Invalid Mode
   	    const x = collectException!CapstoneException(Capstone.create(Arch.x86, ModeFlags(Mode.bit32 | Mode.bigEndian)));
    	assert(x);
    	assert(x.errCode == ErrorCode.InvalidMode);
    }
    {// Invalid Option
        auto cs = Capstone.create(Arch.x86, ModeFlags(Mode.bit32));
	    const x = collectException!CapstoneException(cs.syntax = Syntax.noregname);
        assert(x);
        assert(x.errCode == ErrorCode.InvalidOption);
    }
    {// UnavailableInstructionDetail
        auto cs = new CapstoneImpl!(Arch.x86)(ModeFlags(Mode.bit32)); // DMD v2.083.1 segfaults in build-mode=singleFile if using CapstoneX86 instead
        auto instrs = cs.disasm(X86_CODE32, 0x1000);
        const x = collectException!CapstoneException(instrs[0].detail);
        assert(x);
        assert(x.errCode == ErrorCode.UnavailableInstructionDetail);
    }
}