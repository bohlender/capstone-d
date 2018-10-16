# capstone-d

## What is this?
This package implements idiomatic D bindings for [Capstone](http://www.capstone-engine.org) - the disassembly framework powering many reverse engineering tools. If you do not need the expressivity and safety of D but just the plain C API in D, [non-idiomatic bindings](https://github.com/theoldmoon0602/capstone-d) might be just what you're looking for.

*Note: The development is still in progress and not all architectures are supported yet -- although x86 and ARM work already. While the code is documented, proper documentation will be added as soon as I finish the bindings for the remaining architectures.*

## Examples
### Introductory Example
The following D code uses these bindings for a concise implementation of the introductory [example](http://www.capstone-engine.org/lang_c.html) for the original C library.

```D
import std.format;
import std.stdio;

import capstone;

auto CODE = cast(ubyte[])"\x55\x48\x8b\x05\xb8\x13\x00\x00";

void main(){
	auto cs = new Capstone!(Arch.x86)(ModeFlags(Mode.bit64));
	auto res = cs.disasm(CODE, 0x1000);
	foreach(instr; res)
    	writefln!"0x%x:\t%s\t\t%s"(instr.address, instr.mnemonic, instr.opStr);
}
```
Running this will dissassemble the byte sequence `\x55\x48\x8b\x05\xb8\x13\x00\x00` on a x86_64 architecture and output the following
```
0x1000: push            rbp
0x1001: mov             rax, qword ptr [rip + 0x13b8]
```
### Querying the library's capabilities
If you wanted to determine which architectures the capstone library that you have installed are supported, you could do so as follows:
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
In my case, using the precompiled version 3.0.5 for Archlinux, I this will output
```
Version: 3.0 (lib), 3.0 (bindings)
Querying Support:
arm       : true
arm64     : true
mips      : true
x86       : true
powerPc   : true
sparc     : true
systemZ   : true
xCore     : true
all       : true
diet      : false
x86Reduce : false
```

## How to include this in your project
The examples folder contains a [basic project](https://github.com/bohlender/capstone-d/tree/master/examples/basic) to get you started, but it essentially boils down to adding `capstone-d` as a dependency in the `dub.json` of your project.

## Contribute
Keep in mind that the bindings are still under development, but you can always create an issue if you find bugs or think that something could be improved.
If you want to tackle an issue or contribute to the plugin feel free to create a pull request.
