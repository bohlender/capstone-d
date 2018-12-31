module test.utils;

import std.algorithm: map;
import std.array: join;
import std.format: format;
import std.string: splitLines;
import std.range: zip, enumerate;
import std.string: toUpper;
import std.traits: EnumMembers;
import std.conv: to;

import capstone.api;

/** Most relevant disassembly options

Used for concise configuration of the big regression tests
*/
struct Platform{
	Arch arch;
	Mode mode;
	ubyte[] code;
	string comment;
	Syntax syntax;
	string skipdataMnemonic;
	Callback callback;
}

/// Pretty printing of bytes as in original regression tests
auto bytesToHex(in ubyte[] code){
	return code.map!(i => "0x%.2x".format(i)).join(" ") ~ " "; // ugly terminal space needed to match original
}
///
unittest{
	const CODE = cast(ubyte[])"\xDE\xAD\xBE\xEF";
	assert(CODE.bytesToHex == "0xde 0xad 0xbe 0xef ");
}

/// Pretty printing of mismatches in regression tests
string expectationMismatch(in string expected, in string actual)
in{
	assert(expected != actual);
}
body{
	auto expectedLines = expected.splitLines();
	auto actualLines = actual.splitLines();

	foreach(i, e, a; zip(expectedLines, actualLines).enumerate(1)){
		if(e != a)
			return "Mismatch in line %d\nExpected: %s\n  Actual: %s".format(i,e,a);
	}

	return "Expected %d lines (got %d)".format(expectedLines.length, actualLines.length);
}
///
unittest{
	string expected = "line1\nline2\nline3";
	{// Mismatch in line 2 }
		string actual = "line1\nlin2\nline3";
		auto res = expectationMismatch(expected, actual);
		assert("Mismatch in line 2\nExpected: line2\n  Actual: lin2" == res);
	}
	{// Too short
		string actual = "line1";
		auto res = expectationMismatch(expected, actual);
		assert("Expected 3 lines (got 1)" == res);
	}
	{// Too long
		string actual = "line1\nline2\nline3\nline4";
		auto res = expectationMismatch(expected, actual);
		assert("Expected 3 lines (got 4)" == res);
	}
}

string accessToString(AccessFlags access) {
    string[] accessStrs;
    foreach(accessType; EnumMembers!AccessType[1..$]) // Skip AccessType.invalid
        if(access & accessType)
            accessStrs ~= accessType.to!string.toUpper;
    return accessStrs.join(" | ");
}
///
unittest{
	AccessFlags inv;
	assert("", inv.accessToString);
	auto rw = AccessFlags(AccessType.read | AccessType.write);
	assert("READ | WRITE", rw.accessToString);
}