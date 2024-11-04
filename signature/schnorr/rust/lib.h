// NOTE: You could use https://michael-f-bryan.github.io/rust-ffi-guide/cbindgen.html to generate
// this header automatically from your Rust code.  But for now, we'll just write it by hand.

#include <stdint.h>

void schnorr_sign_hashed_message(uint64_t *m_hashed, uint64_t *sk, uint64_t *sig);
void HashToQuinticExtension(uint64_t *input, size_t input_len, uint64_t *dst);
