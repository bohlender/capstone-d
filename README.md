[![Build Status](https://travis-ci.com/bohlender/capstone-d.svg?branch=master)](https://travis-ci.com/bohlender/capstone-d)
[![codecov](https://codecov.io/gh/bohlender/capstone-d/branch/master/graph/badge.svg)](https://codecov.io/gh/bohlender/capstone-d)

# capstone-d

## What is this?
This package implements idiomatic D bindings for version 4.0 of [Capstone](http://www.capstone-engine.org) - the disassembly framework powering many reverse engineering tools. If you do not need the expressivity and safety of D but just the plain C API in D, [non-idiomatic bindings](https://github.com/theoldmoon0602/capstone-d) might be just what you're looking for.

## Examples
### Introductory Example
The following D code uses these bindings for a concise implementation of the introductory [example](http://www.capstone-engine.org/lang_c.html) for the original C library.

```D
import std.format;
import std.stdio;

import capstone;

auto CODE = cast(ubyte[])"\x55\x48\x8b\x05\xb8\x13\x00\x00";

void main(){
    auto cs = create(Arch.x86, ModeFlags(Mode.bit64));
    auto res = cs.disasm(CODE, 0x1000);
    foreach(instr; res)
        writefln!"0x%x:\t%s\t\t%s"(instr.address, instr.mnemonic, instr.opStr);
}
```
Running this will disassemble the byte sequence `\x55\x48\x8b\x05\xb8\x13\x00\x00` on a x86_64 architecture and output the following
```
0x1000: push            rbp
0x1001: mov             rax, qword ptr [rip + 0x13b8]
```
### Querying the library's capabilities
If you wanted to determine which architectures are supported by the capstone library that you have installed on your system, you could do so as follows:
```D
import std.format;
import std.stdio;
import std.traits;

import capstone;

void main(){
    writefln!"Version: %s (lib), %s (bindings)"(versionOfLibrary, versionOfBindings);
    writeln("Querying Support:");
    foreach(query; EnumMembers!SupportQuery)
        writefln!"%-10s: %s"(query, supports(query));
}
```
In my case, after compiling version 4.0 for Arch Linux, this will output
```
Version: 4.0 (lib), 4.0 (bindings)
Querying Support:
arm       : true
arm64     : true
mips      : true
x86       : true
ppc       : true
sparc     : true
sysz      : true
xcore     : true
m68k      : true
tms320c64x: true
m680x     : true
evm       : true
all       : true
diet      : false
x86reduce : false
```

## How to include this in your project
The package is available in the [D package management](http://code.dlang.org/packages/capstone-d) s.t. it suffices to add `capstone-d` as a dependency in the `dub.json` of your project.
Furthermore, the examples folder contains a [basic project](https://github.com/bohlender/capstone-d/tree/master/examples/basic) to get you started.

## F.A.Q.
> The C API had `cs_op_count` to count an instruction's number of operands of a `givenType`. Why is it missing?

Because this can easily be accomplished in D as follows:
```D
auto number = operands.count!(op => op.type == givenType)
```

> In the C API, if you want to iterate over an instruction's operands of a given type, you first have to determine those operands' indices in the operands array. To this end the C API provides `cs_op_index` to determine the index of an instruction's `k`-th operand of a `givenType` in the operands array. Why is this function missing in these bindings?

Because in D, accessing operands of a given type is easier than using such a function:
```D
auto opsOfGivenType = operands.filter!(op => op.type == givenType)
```

> How to determine an instruction's length in bytes ?

Unlike in the C API, an instruction `instr` does indeed not have a `size` member. In D, arrays & slices have `length`, so you can simpliy use `instr.bytes.length`.

## Contribute
If you find bugs or think that something could be improved, simply create an according issue.
If you want to tackle an issue or contribute to the bindings feel free to create a pull request.
