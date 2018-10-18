module capstone.error;

import std.conv;
import std.exception: enforce, assertNotThrown;
import std.format;
import std.string;

import capstone.internal.api: cs_strerror;

enum ErrorCode {
    Ok = 0,
    OutOfMemory,
    UnsupportedArchitecture,
    InvalidHandle,
    InvalidCshArgument,
    InvalidMode,
    InvalidOption,
    UnavailableInstructionDetail,
    UninitializedDynamicMemoryManagement,
    UnsupportedVersion,
    IrrelevantDataAccessInDietEngine,
    IrrelevantDataAccessInSkipdataMode,
    UnsupportedATnTSyntax,
    UnsupportedIntelSyntax
}

// TODO: Proper error handling
void checkErrorCode(in ErrorCode errno){
    enforce(errno == 0, "Error %s: %s".format(errno.to!int, cs_strerror(errno.to!int).fromStringz));
}

void checkErrorCode(in int errno)
in{
    assertNotThrown!ConvException(errno.to!ErrorCode);
}
body{
    errno.to!ErrorCode.checkErrorCode;
}