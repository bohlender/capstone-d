/// Object-oriented wrapper of registers
module capstone.register;

import std.conv: to;

import capstone.capstone: Capstone;

import capstone.api: diet;
import capstone.error;
import capstone.internal.api: cs_reg_name;

/// Architecture-independent register base class
abstract class Register {
    private const Capstone cs;
    package const int _id;

    private this(in Capstone cs, in int id) {
        this.cs = cs;
        this._id = id;
    }

    /// Retrieves register's id as plain integer
    auto idAsInt() const {return _id;}

    /// Returns friendly string representation of the registers's name
    string name() const {
        if(diet)
            throw new CapstoneException("Register names are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_reg_name(cs.handle, _id).to!string; // TODO: Error handling
    }
}

/** Class template for architecture-specific registers

Note that all architecture-specific instances, like `X86Register`, instantiate and derive from this one.
*/
abstract class RegisterImpl(TId) : Register if(is(TId == enum)) {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }

    /// Retrieves register's id
    auto id() const {return _id.to!TId;}
}