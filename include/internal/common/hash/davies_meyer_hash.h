/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_davies_meyer_hash__H_
#define _flea_davies_meyer_hash__H_

#include "flea/error.h"
#include "flea/types.h"
#include "flea/hash.h"

void flea_hash_davies_meyer_aes128_init(flea_hash_ctx_t* ctx__pt);

flea_err_e THR_flea_hash_davies_meyer_aes128_compression(
  flea_hash_ctx_t* ctx__pt,
  const flea_u8_t* input
) FLEA_ATTRIB_UNUSED_RESULT;

#endif /* h-guard */
