module source.test.utils;

import std.algorithm;
import std.array;
import std.format;

import capstone;

struct Platform{
	Arch arch;
	Mode mode;
	ubyte[] code;
	string comment;
	Syntax syntax;
}

auto bytesToHex(in ubyte[] code){
	return code.map!(i => "0x%.2x".format(i)).join(" ") ~ " "; // ugly terminal space needed to match original
}