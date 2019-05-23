module capstone.internal.evm;

alias evm_insn = int;
alias evm_insn_group = int;

// Instruction structure
struct cs_evm {
    ubyte pop;  // number of items popped from the stack
    ubyte push; // number of items pushed into the stack
    uint fee;   // gas fee for the instruction
}