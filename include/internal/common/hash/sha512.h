/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_sha512__H_
#define _flea_sha512__H_

#include "flea/types.h"

#include "flea/hash.h"

void flea_sha512_encode_hash_state(
  const flea_hash_ctx_t* ctx__pt,
  flea_u8_t*             output,
  flea_al_u8_t           output_len
);

void flea_sha512_init(flea_hash_ctx_t* ctx__pt);

void flea_sha384_init(flea_hash_ctx_t* ctx__pt);

flea_err_t THR_flea_sha512_compression_function(
  flea_hash_ctx_t* ctx__pt,
  const flea_u8_t* input
);

#endif /* h-guard */
