/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "flea/types.h"
#include "flea/hash.h"

flea_err_e THR_flea_md5_compression_function(
  flea_hash_ctx_t* ctx__pt,
  const flea_u8_t* input
);

void flea_md5_init(flea_hash_ctx_t* ctx__pt);

void flea_md5_encode_hash_state(
  const flea_hash_ctx_t* ctx__pt,
  flea_u8_t*             output,
  flea_al_u8_t           output_len
);
