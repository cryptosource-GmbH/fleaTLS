/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/array_util.h"


// TODO: REMOVE BLOCK SIZE, UNIFY MAC_KEY_LEN AND MAC_LEN
// TODO: the last entry (hash id) is actually mac id and we only use it for mac.
// => change back to mac id, hash id for PRF is given by the function below
// __________________________________________________________________
// | FS: ok, can become mac_id again, if that makes the code simpler |
// ------------------------------------------------------------------
//
static const flea_tls__cipher_suite_t cipher_suites[] = {
  {FLEA_TLS_NULL_WITH_NULL_NULL,               FLEA_TLS_NO_CIPHER,
   0, 0,
   0, 0, 0, (flea_mac_id_t) 0, 0},
#ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA
  {FLEA_TLS_RSA_WITH_AES_128_CBC_SHA,          FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA},
#endif
#ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA256
  {FLEA_TLS_RSA_WITH_AES_128_CBC_SHA256,       FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 32, 32, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA},
#endif
#ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA
  {FLEA_TLS_RSA_WITH_AES_256_CBC_SHA,          FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA},
#endif
#ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA256
  {FLEA_TLS_RSA_WITH_AES_256_CBC_SHA256,       FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 32, 32, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA},
#endif
#ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_GCM_SHA256
  {FLEA_TLS_RSA_WITH_AES_128_GCM_SHA256,       FLEA_TLS_AE_CIPHER(flea_gcm_aes128),
   16, 12, 16, 0, 0, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA},
#endif
#ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_GCM_SHA384
  {FLEA_TLS_RSA_WITH_AES_256_GCM_SHA384,       FLEA_TLS_AE_CIPHER(flea_gcm_aes256),
   16, 12, 32, 32, 0, flea_sha384, FLEA_TLS_CS_AUTH_MASK__RSA},
#endif
#ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  {FLEA_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,    FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
#endif
#ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  {FLEA_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,    FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
#endif
#ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  {FLEA_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 32, 32, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
#endif
#ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  {FLEA_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, FLEA_TLS_AE_CIPHER(flea_gcm_aes128),
   16, 12, 16, 0, 0, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
#endif
#ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  {FLEA_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 48, 48, flea_sha384, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
#endif
#ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  {FLEA_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, FLEA_TLS_AE_CIPHER(flea_gcm_aes256),
   16, 12, 32, 32, 0, flea_sha384, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
#endif
};


// TODO: check correctness: so far all cipher suites with hash algorithm > 256
// also use this as prf
flea_hash_id_t flea_tls_get_prf_hash_by_cipher_suite_id(flea_tls__cipher_suite_id_t cs_id__t)
{
  const flea_tls__cipher_suite_t* cs__pt = flea_tls_get_cipher_suite_by_id(cs_id__t);

  if(cs__pt->hash_algorithm == flea_sha384)
  {
    return flea_sha384;
  }
  else if(cs__pt->hash_algorithm == flea_sha512)
  {
    return flea_sha512;
  }
  return flea_sha256;
}

const flea_tls__cipher_suite_t* flea_tls_get_cipher_suite_by_id(flea_tls__cipher_suite_id_t id__t)
{
  flea_u16_t i;

  for(i = 0; i < sizeof(cipher_suites); i++)
  {
    if(cipher_suites[i].id == id__t)
    {
      return &(cipher_suites[i]);
    }
  }

  // should never happen but compiler gives a warning.
  // TODO: have to make sure that the compiled cs ids are the same as the
  // compiled cs entries in cipher_suites[]
  return &(cipher_suites[0]);
}

flea_pk_key_type_t flea_tls__get_key_type_by_cipher_suite_id(flea_tls__cipher_suite_id_t id__t)
{
  if(flea_tls_get_cipher_suite_by_id(id__t)->mask & FLEA_TLS_CS_AUTH_MASK__RSA)
  {
    return flea_rsa_key;
  }
  return flea_ecc_key;
}

flea_tls__kex_method_t flea_tls_get_kex_method_by_cipher_suite_id(flea_tls__cipher_suite_id_t id__t)
{
  // TODO (JR): ähnliche CipherSuites haben vermutlich ähnliche hex-values =>
  // man könnte ranges definieren, in denen eine bestimmte kex_method
  // zurückgegeben wird
  // => selbiges für get_prf_hash
  // if(id__t == FLEA_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
  if((id__t >> 8) == 0xC0)
  {
    return FLEA_TLS_KEX_ECDHE;
  }
  return FLEA_TLS_KEX_RSA;
}

flea_err_t THR_flea_tls_get_cipher_suite_by_id(
  flea_tls__cipher_suite_id_t      id,
  const flea_tls__cipher_suite_t** result__pt
)
{
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(cipher_suites); i++)
  {
    if(cipher_suites[i].id == id)
    {
      // return &cipher_suites[i];
      *result__pt = &cipher_suites[i];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("invalid cipher suite id", FLEA_ERR_TLS_INV_CIPH_SUITE);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_get_key_block_len_from_cipher_suite_id(
  flea_tls__cipher_suite_id_t id,
  flea_al_u8_t*               result_key_block_len__palu8
)
{
  const flea_tls__cipher_suite_t* ct__pt;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_tls_get_cipher_suite_by_id(id, &ct__pt));
  *result_key_block_len__palu8 = ct__pt->mac_key_size * 2 + ct__pt->enc_key_size * 2;

  // if(id == FLEA_TLS_RSA_WITH_AES_128_GCM_SHA256)
  if(FLEA_TLS_IS_AE_CIPHER(ct__pt->cipher))
  {
    *result_key_block_len__palu8 = ct__pt->enc_key_size * 2 + 16;
  }
  FLEA_THR_FIN_SEC_empty();
}
