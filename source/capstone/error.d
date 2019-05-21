/// Exceptions and handling of Capstone-internal errors
module capstone.error;

import std.conv: to;
import std.format: format;
import std.string: fromStringz;

import capstone.internal.api: cs_strerror;

/** Original error codes of the wrapped Capstone library

Note that some cannot occur by design of the bindings, e.g. using an invalid handle to the Capstone engine.
*/
enum ErrorCode {
    Ok = 0,                                 /// Not an error (will not occur in an exception)
    OutOfMemory,                            /// Ran out of memory, e.g. when disassembling a long byte-stream
    UnsupportedArchitecture,                /// Requested an unsupported architecture, e.g. when compiled without corresponding support
    InvalidHandle,                          /// Using an invalid handle to a Capstone engine instance (cannot happen)
    InvalidCshArgument,                     /// Using an invalid handle as argument (cannot happen)
    InvalidMode,                            /// Requested invalid/unsupported mode, e.g. `Mode.bigEndian` for `Arch.x86`
    InvalidOption,                          /// Using invalid/unsupported option
    UnavailableInstructionDetail,           /// Trying to access unavailable instruction detail
    UninitializedDynamicMemoryManagement,   /// Dynamic memory management uninitialised (cannot happen - not implemented yet)
    UnsupportedVersion,                     /// Mismatch of bindings and library version
    IrrelevantDataAccessInDietEngine,       /// Accessing data that is unavailable/invalid in diet mode
    IrrelevantDataAccessInSkipdataMode,     /// Accessing data that is irrelevant for "data" instruction in SKIPDATA mode (cannot happen)
    UnsupportedATnTSyntax,                  /// Requesting unsupported AT&T syntax (opt-out at compile time)
    UnsupportedIntelSyntax,                 /// Requesting unsupported Intel syntax (opt-out at compile time)
	UnsupportedMasmSyntax,                  /// Requesting unsupported MASM syntax (opt-out at compile time)
}

/// Exception thrown on errors in the wrapped Capstone library
class CapstoneException : Exception {
    /// Denotes the kind of error
    const ErrorCode errCode;

    package this(string msg, in ErrorCode errno, string file = __FILE__, size_t line = __LINE__, Throwable next = null){
        super(msg, file, line, next);
        this.errCode = errno;
    }

    package this(in ErrorCode errno, string file = __FILE__, size_t line = __LINE__, Throwable next = null){
        const msg = format!"Capstone Error %d: %s"(errno, cs_strerror(errno.to!int).fromStringz);
        super(msg, file, line, next);
        this.errCode = errno;
    }
}

/// Handles Capstone's error codes and raises corresponding exceptions
package void checkErrno(in int errno, string file = __FILE__, size_t line = __LINE__, Throwable next = null){
    auto code = errno.to!ErrorCode;
    if(code != ErrorCode.Ok)
        throw new CapstoneException(code, file, line, next);
}