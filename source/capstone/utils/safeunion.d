/** A safe union, or variant, disallowing reading invalid types

The C API implements operand values as regular unions, enabling (mis)interpretation of the stored value in any of the
encompassed types. This implementation provides a safer union that throws when interpreting the union's value in a
different type than it was stored as.
*/
module capstone.utils.safeunion;

import std.traits: FieldTypeTuple, FieldNameTuple;
import std.meta;
import std.exception: enforce, basicExceptionCtors, assertThrown, assertNotThrown;

/** Constructs a `SafeUnion` wrapping the specified union type

Enables access of the stored value through the field names of the wrapped union.
*/
template SafeUnion(U) if (is(U == union)) {
	template FieldSpec(T, string s) {
		alias Type = T;
		alias name = s;
	}

	template parseSpecs(Specs...) {
		enum midIdx = Specs.length/2;
		static if(Specs.length == 0)
			alias parseSpecs = AliasSeq!();
		else static if(is(Specs[0]))
			alias parseSpecs = AliasSeq!(FieldSpec!(Specs[0], Specs[midIdx]), parseSpecs!(Specs[1..midIdx], Specs[midIdx+1..$]));
		else
			static assert(0, "Attempted to instantiate MultiValue with an invalid argument: " ~ Specs[0].stringof ~ " " ~ Specs[midIdx].stringof);
	}

	alias fieldSpecs = parseSpecs!(FieldTypeTuple!U, FieldNameTuple!U);
	alias extractType(alias spec) = spec.Type;
	alias extractName(alias spec) = spec.name;
	alias FieldTypes = staticMap!(extractType, fieldSpecs);
	alias fieldNames = staticMap!(extractName, fieldSpecs);

	struct SafeUnion{
		private U wrapped;
		private string curType;

		// Generate getters (by identifier)
		static foreach(spec; fieldSpecs){
			mixin("@property " ~ spec.name ~"() const {
				auto expectedType = spec.Type.stringof;
				enforce!SafeUnionException(curType == expectedType,
				\"Trying to read a '\" ~ spec.Type.stringof ~ \"' but a '\" ~ curType ~ \"' is stored\");
				return wrapped." ~ spec.name ~ ";
			}");
		}

		// Generate setters
		static foreach(spec; fieldSpecs){
			mixin("@property " ~ spec.name ~ "(spec.Type val){wrapped." ~ spec.name ~ " = val; curType = spec.Type.stringof;}");
		}
	}
}
///
unittest{
	import capstone.api;
	import capstone.x86;

	auto cs = new CapstoneX86(ModeFlags(Mode.bit32));
	auto x86reg = new X86Register(cs, X86RegisterId.eip);

	SafeUnion!X86OpValue safeVal;
	assertThrown(safeVal.imm);    	   // Not initialised
	safeVal.reg = x86reg;
	assertThrown(safeVal.imm);    	   // cannot access the `long` since a `X86Register` is currently stored
	safeVal.imm = 42;
	assertNotThrown(safeVal.imm);      // can access the `long` now

	// Corresponding operations on a regular union go unnoticed
	X86OpValue unsafeVal;
	unsafeVal.reg = x86reg;
	assertNotThrown(unsafeVal.imm);
}

/// Thrown on misuse of `SafeUnion`
class SafeUnionException : Exception{
	///
	mixin basicExceptionCtors;
}