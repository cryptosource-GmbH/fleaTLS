/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_mac__H_
#define _flea_mac__H_


#include "internal/common/default.h"
#include "flea/block_cipher.h"
#include "flea/hash.h"
#include "internal/common/mac_int.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Supported MAC algorithms
 */
typedef enum { flea_hmac_md5, flea_hmac_sha1, flea_hmac_sha224, flea_hmac_sha256, flea_hmac_sha384, flea_hmac_sha512,
               flea_cmac_des, flea_cmac_tdes_2key, flea_cmac_tdes_3key, flea_cmac_aes128, flea_cmac_aes192,
               flea_cmac_aes256 } flea_mac_id_e;


#ifdef FLEA_HEAP_MODE
# define flea_mac_ctx_t__INIT(__p) FLEA_ZERO_STRUCT(__p)
#else
# define flea_mac_ctx_t__INIT(__p) FLEA_ZERO_STRUCT(__p)


#endif // ifdef FLEA_HEAP_MODE

flea_al_u8_t flea_mac__get_output_length_by_id(flea_mac_id_e mac_id__e);

/**
 * Create a MAC context object for either MAC computation of verification.
 *
 * @param ctx pointer to the context object to create
 * @param id the ID of the MAC algorithm to use
 * @param key pointer to the MAC key to use
 * @param key_len length of key
 *
 * @return flea error code
 */
flea_err_e THR_flea_mac_ctx_t__ctor(
  flea_mac_ctx_t*  ctx,
  flea_mac_id_e    id,
  const flea_u8_t* key,
  flea_al_u16_t    key_len
);

/**
 * Destroy a MAC object.
 *
 * @param ctx pointer to the context object to destroy
 *
 */
void flea_mac_ctx_t__dtor(flea_mac_ctx_t* ctx);

/**
 * Feed data to a MAC object for either MAC computation of verification.
 *
 * @param ctx pointer to the context object to use
 * @param dta pointer to the data to be authenticated
 * @param dta_len length of dta
 *
 * @return flea error code
 */
flea_err_e THR_flea_mac_ctx_t__update(
  flea_mac_ctx_t*  ctx,
  const flea_u8_t* dta,
  flea_dtl_t       dta_len
);

/**
 * Finalize a MAC computation.
 *
 * @param ctx pointer to the context object to use
 * @param result pointer to the memory area where to store the MAC value, needs
 * to have at least FLEA_MAC_MAX_OUTPUT_LENGTH bytes allocated
 * @param result_len the caller must provide a pointer to a value representing
 * the available length of result, upon function return this value will be
 * updated to the number of bytes written to result. If the length provided by
 * the caller is shorter than the natural output length of the chosen MAC, then
 * the MAC will be truncated accordingly. If the length provided by the caller
 * is longer than the MAC's natural output length, then the length value will be
 * set to the MAC's natural output length and the full MAC value will be written.
 *
 * @return flea error code
 */
flea_err_e THR_flea_mac_ctx_t__final_compute(
  flea_mac_ctx_t* ctx,
  flea_u8_t*      result,
  flea_al_u8_t*   result_len
);

/**
 * Finalize MAC verification.
 *
 * @param ctx pointer to the context object to use
 * @param mac pointer to the MAC value to be verified
 * @param mac_len the length of mac
 *
 * @return flea error code: FLEA_ERR_FINE if the verification succeeded,
 * FLEA_ERR_INV_MAC (or potentiall other error codes) if it failed
 */
flea_err_e THR_flea_mac_ctx_t__final_verify(
  flea_mac_ctx_t*  ctx,
  const flea_u8_t* mac,
  flea_al_u8_t     mac_len
);

/**
 * Compute a MAC over a data string.
 *
 * @param id the ID of the MAC algorithm to use
 * @param key pointer to the key to use
 * @param key_len length of key
 * @param dta pointer to the data to be authenticated
 * @param dta_len length of dta
 * @param result pointer to the memory area where to store the MAC value, needs
 * to have at least FLEA_MAC_MAX_OUTPUT_LENGTH bytes allocated
 * @param result_len the caller must provide a pointer to a value representing
 * the available length of result, upon function return this value will be
 * updated to the number of bytes written to result
 *
 * @return flea error code
 */
flea_err_e THR_flea_mac__compute_mac(
  flea_mac_id_e    id,
  const flea_u8_t* key,
  flea_al_u16_t    key_len,
  const flea_u8_t* dta,
  flea_dtl_t       dta_len,
  flea_u8_t*       result,
  flea_al_u8_t*    result_len
);

/**
 * Verify a MAC over a data string.
 *
 * @param id the ID of the MAC algorithm to use
 * @param key pointer to the key to use
 * @param key_len length of key
 * @param dta pointer to the data to be authenticated
 * @param dta_len length of dta
 * @param mac pointer to the MAC value to be verified
 * @param mac_len the length of mac
 *
 * @return flea error code: FLEA_ERR_FINE if the verification succeeded, FLEA_ERR_INV_MAC if it failed
 */
flea_err_e THR_flea_mac__verify_mac(
  flea_mac_id_e    id,
  const flea_u8_t* key,
  flea_al_u16_t    key_len,
  const flea_u8_t* dta,
  flea_dtl_t       dta_len,
  const flea_u8_t* mac,
  flea_al_u8_t     mac_len
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
