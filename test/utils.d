module test.utils;

import std.algorithm: map;
import std.array: join;
import std.format: format;
import std.string: splitLines;
import std.range: zip, enumerate;

import capstone;

struct Platform{
	Arch arch;
	Mode mode;
	ubyte[] code;
	string comment;
	Syntax syntax;
	string skipdataMnemonic;
}

auto bytesToHex(in ubyte[] code){
	return code.map!(i => "0x%.2x".format(i)).join(" ") ~ " "; // ugly terminal space needed to match original
}

string expectationMismatch(in string expected, in string actual)
in{
	assert(expected != actual);
}
body{
	auto expectedLines = expected.splitLines();
	auto actualLines = actual.splitLines();

	const formatStr = "Mismatch in line %d\nExpected: %s\n  Actual: %s";
	foreach(i, e, a; zip(expectedLines, actualLines).enumerate(1)){
		if(e != a)
			return formatStr.format(i,e,a);
	}

	if(actualLines.length < expectedLines.length){
		auto i = actualLines.length;
		return formatStr.format(i,expectedLines[i],"");
	}else{
		auto i = expectedLines.length;
		return formatStr.format(i,"",actualLines[i]);
	}
}