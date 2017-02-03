/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/hash/davies_meyer_hash.h"
#include "flea/hash.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "internal/common/block_cipher/aes.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include <string.h>

#ifdef FLEA_HAVE_DAVIES_MEYER_HASH
void flea_hash_davies_meyer_aes128_init(flea_hash_ctx_t *ctx__pt)
{
  memset(ctx__pt->hash_state, 0, 16);
}

flea_err_t THR_flea_hash_davies_meyer_aes128_compression(flea_hash_ctx_t *ctx__pt, const flea_u8_t *input)
{
  FLEA_DECL_OBJ(aes_ctx, flea_ecb_mode_ctx_t);
  FLEA_DECL_BUF(tmp_state, flea_u8_t, FLEA_AES_BLOCK_LENGTH);
  FLEA_THR_BEG_FUNC();


  FLEA_ALLOC_BUF(tmp_state, FLEA_AES_BLOCK_LENGTH);

  FLEA_CCALL(THR_flea_ecb_mode_ctx_t__ctor(&aes_ctx, flea_aes128, input, FLEA_AES128_KEY_BYTE_LENGTH, flea_encrypt));

  flea_aes_encrypt_block(&aes_ctx, (flea_u8_t *) ctx__pt->hash_state, tmp_state);

  flea__xor_bytes_in_place((flea_u8_t *) ctx__pt->hash_state, tmp_state, FLEA_AES_BLOCK_LENGTH);

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(tmp_state);
    flea_ecb_mode_ctx_t__dtor(&aes_ctx);
  );
}

#endif // #ifdef FLEA_HAVE_DAVIES_MEYER_HASH
