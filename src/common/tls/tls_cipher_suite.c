/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_ciph_suite.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/array_util.h"
#include "internal/common/tls/tls_int.h"


#ifdef FLEA_HAVE_TLS


static const flea_tls__cipher_suite_t cipher_suites[] = {
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA
  {flea_tls_rsa_with_aes_128_cbc_sha,          FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__RSA},
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA256
  {flea_tls_rsa_with_aes_128_cbc_sha256,       FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 32, 32, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__RSA},
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA
  {flea_tls_rsa_with_aes_256_cbc_sha,          FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__RSA},
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA256
  {flea_tls_rsa_with_aes_256_cbc_sha256,       FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 32, 32, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__RSA},
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_GCM_SHA256
  {flea_tls_rsa_with_aes_128_gcm_sha256,       FLEA_TLS_AE_CIPHER(flea_gcm_aes128),
   16, 12, 16, 0, 0, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__RSA},
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_GCM_SHA384
  {flea_tls_rsa_with_aes_256_gcm_sha384,       FLEA_TLS_AE_CIPHER(flea_gcm_aes256),
   16, 12, 32, 32, 0, flea_sha384, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__RSA},
# endif

# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  {flea_tls_ecdhe_rsa_with_aes_128_cbc_sha,    FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  {flea_tls_ecdhe_rsa_with_aes_256_cbc_sha,    FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  {flea_tls_ecdhe_rsa_with_aes_128_cbc_sha256, FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 32, 32, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  {flea_tls_ecdhe_rsa_with_aes_256_cbc_sha384, FLEA_TLS_BLOCK_CIPHER(flea_aes256),
   16, 16, 32, 48, 48, flea_sha384, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  {flea_tls_ecdhe_rsa_with_aes_128_gcm_sha256, FLEA_TLS_AE_CIPHER(flea_gcm_aes128),
   16, 12, 16, 0, 0, flea_sha256, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  {flea_tls_ecdhe_rsa_with_aes_256_gcm_sha384, FLEA_TLS_AE_CIPHER(flea_gcm_aes256),
   16, 12, 32, 32, 0, flea_sha384, FLEA_TLS_CS_AUTH_MASK__RSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  {flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha,  FLEA_TLS_BLOCK_CIPHER(flea_aes128),
   16, 16, 16, 20, 20, flea_sha1, FLEA_TLS_CS_AUTH_MASK__ECDSA | FLEA_TLS_CS_KEX_MASK__ECDHE},
# endif
};


flea_hash_id_e flea_tls_get_prf_hash_by_cipher_suite_id(flea_tls_cipher_suite_id_t cs_id__t)
{
# ifdef FLEA_HAVE_SHA384_512

  /** compile time restrictions prevent the instantiation of wrong cipher
   * suites here
   */
  const flea_tls__cipher_suite_t* cs__pt = flea_tls_get_cipher_suite_by_id(cs_id__t);

  if(cs__pt->hash_algorithm == flea_sha384)
  {
    return flea_sha384;
  }
  else if(cs__pt->hash_algorithm == flea_sha512)
  {
    return flea_sha512;
  }
# endif /* ifdef FLEA_HAVE_SHA384_512 */
  return flea_sha256;
}

const flea_tls__cipher_suite_t* flea_tls_get_cipher_suite_by_id(flea_tls_cipher_suite_id_t id__t)
{
  flea_u16_t i;

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(cipher_suites); i++)
  {
    if(cipher_suites[i].id == id__t)
    {
      return &(cipher_suites[i]);
    }
  }
  /* this cannot happen, just to prevent compiler warning: */
  return NULL;
}

/**
 * the ciphersuite must be known to flea at compile time in this function.
 */

/*flea_pk_key_type_e flea_tls__get_key_type_by_cipher_suite_id(flea_tls_cipher_suite_id_t id__t)
{
  if(flea_tls_get_cipher_suite_by_id(id__t)->mask & FLEA_TLS_CS_AUTH_MASK__RSA)
  {
    return flea_rsa_key;
  }
  return flea_ecc_key;
}*/

flea_bool_t flea_tls__does_priv_key_type_fit_to_ciphersuite(
  flea_tls_cipher_suite_id_t id__t,
  flea_pk_key_type_e         key_type__e
)
{
  const flea_tls__cipher_suite_t* cs__pt = flea_tls_get_cipher_suite_by_id(id__t);
  flea_u32_t is_rsa_cs__u32;

  if(cs__pt == NULL)
  {
    return FLEA_FALSE;
  }
  is_rsa_cs__u32 = cs__pt->mask & FLEA_TLS_CS_AUTH_MASK__RSA;
  if(key_type__e == flea_rsa_key)
  {
    if(is_rsa_cs__u32)
    {
      return FLEA_TRUE;
    }
    return FLEA_FALSE;
  }
  else  /* EC suite */
  {
    if(is_rsa_cs__u32)
    {
      return FLEA_FALSE;
    }
    else
    {
      return FLEA_TRUE;
    }
  }
}

flea_tls__kex_method_t flea_tls_get_kex_method_by_cipher_suite_id(flea_tls_cipher_suite_id_t id__t)
{
  if(flea_tls_get_cipher_suite_by_id(id__t)->mask & FLEA_TLS_CS_KEX_MASK__RSA)
  {
    return FLEA_TLS_KEX_RSA;
  }
  return FLEA_TLS_KEX_ECDHE;
}

flea_tls_kex_e flea_tls__get_kex_and_auth_method_by_cipher_suite_id(flea_tls_cipher_suite_id_t id__t)
{
  const flea_tls__cipher_suite_t* cs__pt = flea_tls_get_cipher_suite_by_id(id__t);

  if(cs__pt->mask & FLEA_TLS_CS_AUTH_MASK__RSA)
  {
    if(cs__pt->mask & FLEA_TLS_CS_KEX_MASK__RSA)
    {
      return flea_tls_kex__rsa;
    }
  }
  return flea_tls_kex__ecdhe_rsa;
}

flea_err_e THR_flea_tls_get_cipher_suite_by_id(
  flea_tls_cipher_suite_id_t       id,
  const flea_tls__cipher_suite_t** result__pt
)
{
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(cipher_suites); i++)
  {
    if(cipher_suites[i].id == id)
    {
      *result__pt = &cipher_suites[i];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("invalid cipher suite id", FLEA_ERR_TLS_INV_CIPH_SUITE);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_get_key_block_len_from_cipher_suite_id(
  flea_tls_cipher_suite_id_t id,
  flea_al_u16_t*             result_key_block_len__palu16
)
{
  const flea_tls__cipher_suite_t* ct__pt;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_tls_get_cipher_suite_by_id(id, &ct__pt));
  *result_key_block_len__palu16 = ct__pt->mac_key_size * 2 + ct__pt->enc_key_size * 2;

  if(FLEA_TLS_IS_AE_CIPHER(ct__pt->cipher))
  {
    *result_key_block_len__palu16 = ct__pt->enc_key_size * 2 + 2 * FLEA_CONST_TLS_GCM_FIXED_IV_LEN;
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_TLS */
