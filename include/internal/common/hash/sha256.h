/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_sha256_H_
#define _flea_sha256_H_

#include "flea/types.h"
#include "flea/hash.h"

void flea_sha256_encode_hash_state(const flea_hash_ctx_t* ctx__t, flea_u8_t* output,  flea_al_u8_t output_len);

void flea_sha256_init( flea_hash_ctx_t* ctx__t);

void flea_sha224_init( flea_hash_ctx_t* ctx__t);

flea_err_t THR_flea_sha256_compression_function( flea_hash_ctx_t* ctx__t, const flea_u8_t* input);

#endif /* h-guard */
