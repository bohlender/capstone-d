/** A tagged union on top of `std.variant.Algebraic`

The C API implements operand values as regular unions, enabling (mis)interpretation of the stored value in any of the
encompassed types. This implementation provides a safer union that throws when interpreting the union's value in a
different type than it was stored as.
*/
module capstone.utils.tagged_union;

import std.meta: AliasSeq, staticMap;
import std.format: format;
import std.exception: enforce, basicExceptionCtors, assertThrown, assertNotThrown;
import std.variant: Algebraic;

private enum bool distinctFieldNames(names...) = __traits(compiles,{
    static foreach (name; names)
        static if (is(typeof(name) : string))
            mixin("enum int" ~ name ~ " = 0;");
});

private enum bool distinctTypeNames(names...) = __traits(compiles,{
    static foreach (name; names)
        static if (is(name))
            mixin("enum int" ~ name.mangleof ~ " = 0;");
});

unittest{
	assert(distinctFieldNames!("asdf","asd",int,"asdg"));
	assert(!distinctFieldNames!("asdf","asd","asdf"));
	assert(distinctTypeNames!(int,long,string,"string",uint));
	assert(!distinctTypeNames!(int,long,uint,int));
}

/** Constructs a `TaggedUnion` with the specifiedn types and identifiers

In contrast to a plain `std.variant.Algebraic`, this one is not only parameterised by types but also by identifiers.
This enables access of the stored value via the identifiers - just as for regular unions.
*/
template TaggedUnion(Specs...) if (distinctFieldNames!Specs && distinctTypeNames!Specs){
	template FieldSpec(T, string s){
		alias Type = T;
		alias name = s;
	}
	
	template parseSpecs(Specs...){
		static if(Specs.length==0){
			alias parseSpecs = AliasSeq!();
		}else static if(is(Specs[0])){
			alias parseSpecs = AliasSeq!(FieldSpec!(Specs[0..2]), parseSpecs!(Specs[2..$]));
		}else{
			static assert(0, "Attempted to instantiate TaggedUnion with an invalid argument: " ~ Specs[0].stringof);
		}
		
	}

	alias fieldSpecs = parseSpecs!Specs;
	alias extractType(alias spec) = spec.Type;
	alias extractName(alias spec) = spec.name;
	alias Types = staticMap!(extractType, fieldSpecs);
	alias names = staticMap!(extractName, fieldSpecs);

	struct TaggedUnion{
		private Algebraic!Types wrapped;

		// Generate constructors
		static foreach(T; Types){
			this(T val){wrapped = val;}
		}
		
		// Generate getter (by type)
		@property auto get(InnerType)() const {
			return wrapped.get!(InnerType);			
		}

		// Generate getters (by identifier)
		static foreach(spec; fieldSpecs){
			mixin("@property auto " ~ spec.name ~"() const {
				enforce!TaggedUnionException(wrapped.type == typeid(spec.Type),
				\"Trying to read a '\" ~ spec.Type.stringof ~ \"' but a '\" ~ wrapped.type.toString ~ \"' is stored\");
				return wrapped.get!(spec.Type);
			}");
		}

		// Generate setters
		static foreach(i, spec; fieldSpecs){
			mixin("@property auto " ~ spec.name ~ "(spec.Type val){wrapped = val;}");
		}
	}
}
///
unittest{
	import capstone.x86;

	alias SafeOpValue = TaggedUnion!(X86Register, "reg", long, "imm");
	auto safeVal = SafeOpValue(X86Register.eip);
	assertThrown(safeVal.imm);    	   // cannot access the `long` since a `X86Register` is currently stored
	safeVal.imm = 42;
	assertNotThrown(safeVal.imm);      // can access the `long` now
	assertNotThrown(safeVal.get!long); // also accessible by type
	
	// Corresponding operations on a regular union go unnoticed
	union UnsafeOpValue{X86Register reg; long imm;}
	auto unsafeVal = UnsafeOpValue(X86Register.eip);
	assertNotThrown(unsafeVal.imm);
}

/// Thrown on misuse of `TaggedUnion`
class TaggedUnionException : Exception{
	///
	mixin basicExceptionCtors;
}