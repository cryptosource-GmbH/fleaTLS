/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/array_util.h"


// TODO: REMOVE BLOCK SIZE, UNIFY MAC_KEY_LEN AND MAC_LEN
const flea_tls__cipher_suite_t cipher_suites[4] = {
  {TLS_NULL_WITH_NULL_NULL,         (flea_block_cipher_id_t) 0,
   0, 0,
   0, 0, 0, (flea_mac_id_t) 0 /*, (flea_hash_id_t) 0, (flea_tls__prf_algorithm_t) 0*/},
  {TLS_RSA_WITH_AES_256_CBC_SHA256, flea_aes256,
   16, 16, 32, 32, 32, flea_hmac_sha256 /*flea_sha256, FLEA_TLS_PRF_SHA256*/},
  {TLS_RSA_WITH_AES_256_CBC_SHA,    flea_aes256,
   16, 16, 32, 20, 20, flea_hmac_sha1},
  {TLS_RSA_WITH_AES_128_GCM_SHA256, (flea_block_cipher_id_t) 0, 16, 12, 16, 0, (flea_mac_id_t) 0} // TODO: generalize to allow meaningful gcm entry
};

const flea_tls__cipher_suite_t* flea_tls_get_cipher_suite_by_id(flea_tls__cipher_suite_id_t id)
{
  flea_al_u8_t i;

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(cipher_suites); i++)
  {
    if(cipher_suites[i].id == id)
    {
      return &cipher_suites[i];
    }
  }
  return NULL;
}

flea_err_t THR_flea_tls_get_key_block_len_from_cipher_suite_id(
  flea_tls__cipher_suite_id_t id,
  flea_al_u8_t*               result_key_block_len__palu8
)
{
  const flea_tls__cipher_suite_t* ct__pt = flea_tls_get_cipher_suite_by_id(id);

  FLEA_THR_BEG_FUNC();
  if(ct__pt == NULL)
  {
    FLEA_THROW("invalid cipher suite id", FLEA_ERR_INT_ERR);
  }
  *result_key_block_len__palu8 = ct__pt->mac_key_size * 2 + ct__pt->enc_key_size * 2;

  // TODO: choose better approach
  if(id == TLS_RSA_WITH_AES_128_GCM_SHA256)
  {
    *result_key_block_len__palu8 = ct__pt->enc_key_size * 2 + 16;
  }
  FLEA_THR_FIN_SEC_empty();
}
