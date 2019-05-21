/// Object-oriented wrapper of instruction groups
module capstone.instructiongroup;

import std.conv: to;

import capstone.capstone: Capstone;

import capstone.api: diet;
import capstone.error;
import capstone.internal.api: cs_group_name;

/// Architecture-independent instruction group base class
abstract class InstructionGroup {
    private const Capstone cs;
    package const int _id;

    private this(in Capstone cs, in int id) {
        this.cs = cs;
        this._id = id;
    }

    /// Retrieves instruction group's id as plain integer
    auto idAsInt() const {return _id;}

    /** Returns friendly string representation of the instruction group's name

    When in diet mode, this API is irrelevant because the engine does not store group names.
    */
    string name() const {
        if(diet)
            throw new CapstoneException("Group names are not stored when running Capstone in diet mode",
                ErrorCode.IrrelevantDataAccessInDietEngine);
        return cs_group_name(cs.handle, _id).to!string; // TODO: Error handling
    }
}

/** Class template for architecture-specific instruction groups

Note that all architecture-specific instances, like `X86InstructionGroup`, instantiate and derive from this one.
*/
abstract class InstructionGroupImpl(TId) : InstructionGroup if(is(TId == enum)) {
    package this(in Capstone cs, in int id) {
        super(cs, id);
    }

    /// Retrieves instruction group's id
    auto id() const {return _id.to!TId;}
}