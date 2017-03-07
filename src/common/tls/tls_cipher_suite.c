/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/types.h"
#include "flea/array_util.h"


// TODO: REMOVE BLOCK SIZE, UNIFY MAC_KEY_LEN AND MAC_LEN
const flea_tls__cipher_suite_t cipher_suites[3] = {
  {TLS_NULL_WITH_NULL_NULL,         (flea_block_cipher_id_t) 0,
   0, 0,
   0, 0, 0, (flea_mac_id_t) 0 /*, (flea_hash_id_t) 0, (flea_tls__prf_algorithm_t) 0*/},
  {TLS_RSA_WITH_AES_256_CBC_SHA256, flea_aes256,
   16, 16, 32, 32, 32, flea_hmac_sha256 /*flea_sha256, FLEA_TLS_PRF_SHA256*/},
  {TLS_RSA_WITH_AES_256_CBC_SHA,    flea_aes256,
   16, 16, 32, 20, 20, flea_hmac_sha1}
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
