#ifndef _flea_pkcs8__H_
#define _flea_pkcs8__H_

#include "flea/types.h"
#include "flea/privkey.h"

#ifdef FLEA_HAVE_ASYM_ALGS
# ifdef __cplusplus
extern "C" {
# endif

/**
 * Construct a private key from a DER encoded PKCS#8 structure.
 *
 * @param key the key to construct
 * @param der_key the DER encoded structure
 * @param der_key_len the length of the DER encoded structure
 */
flea_err_e THR_flea_private_key_t__ctor_pkcs8(
  flea_private_key_t* key,
  const flea_u8_t*    der_key,
  flea_al_u16_t       der_key_len
);

/**
 * Construct a public key from a DER encoded PKCS#8 structure.
 *
 * @param key the key to construct
 * @param der_key the DER encoded structure
 * @param der_key_len the length of the DER encoded structure
 */
flea_err_e THR_flea_public_key_t__ctor_pkcs8(
  flea_public_key_t* key,
  const flea_u8_t*   der_key,
  flea_al_u16_t      der_key_len
);

# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
