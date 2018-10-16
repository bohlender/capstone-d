module capstone.utils;

import std.meta: AliasSeq, staticMap;
import std.format: format;
import std.exception: enforce;

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
		import std.variant: Algebraic;
		private Algebraic!Types wrapped;

		// Generate constructors
		static foreach(T; Types){
			this(T val){wrapped = val;}
		}

		// Generate getters
		static foreach(spec; fieldSpecs){
			mixin("@property auto " ~ spec.name ~"() const {
				enforce(wrapped.type == typeid(spec.Type), \"Trying to read a '\" ~ spec.Type.stringof ~ \"' but a '\" ~ wrapped.type.toString ~ \"' is stored\");
				return wrapped.get!(spec.Type);
			}");
		}

		// Generate setters
		static foreach(i, spec; fieldSpecs){
			mixin("@property auto " ~ spec.name ~ "(spec.Type val){wrapped = val;}");
		}
	}
}