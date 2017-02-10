/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_sha1__H_
#define _flea_sha1__H_

#include "flea/hash.h"
flea_err_t THR_flea_sha1_compression_function(
  flea_hash_ctx_t* ctx__pt,
  const flea_u8_t* input__pc_u8
);

void flea_sha1_init(flea_hash_ctx_t* ctx__pt);

#endif /* h-guard */
