#include "textflag.h"

// AddFAsm(lhs, rhs GoldilocksField) GoldilocksField
TEXT ·AddFAsm(SB), NOSPLIT, $0-24
    // Load lhs and rhs into registers
    MOVQ lhs+0(FP), AX
    MOVQ rhs+8(FP), BX

    // Perform the addition
    ADDQ BX, AX
    JNC no_overflow

    // Handle overflow
    ADDQ $0xffffffff, AX

no_overflow:
    // Store the result
    MOVQ AX, ret+16(FP)
    RET
