#include <stdint.h>
#include <stddef.h>

void hash_n_to_hash_no_pad(const uint64_t *data, size_t len, uint64_t *dst);
void hash_no_pad(const uint64_t *input, size_t input_len, uint64_t *dst);
void schnorr_sign_hashed_message(const uint64_t *m_hashed, const uint64_t *sk, uint64_t *sig);
void hash_to_quintic_extension(const uint64_t *input, size_t input_len, uint64_t *dst);
void schnorr_pk_from_sk(const uint64_t *input, uint64_t *dst);
