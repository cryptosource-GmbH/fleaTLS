#ifndef _flea_pkcs8__H_
#define _flea_pkcs8__H_

#include "flea/types.h"
#include "flea/privkey.h"

#ifdef FLEA_HAVE_ASYM_ALGS
# ifdef __cplusplus
extern "C" {
# endif


flea_err_t
THR_flea_private_key_t__ctor_pkcs8(flea_private_key_t *key__pt, const flea_u8_t *der_key__pcu8, flea_al_u16_t der_key_len__alu16);

flea_err_t
THR_flea_public_key_t__ctor_pkcs8(flea_public_key_t *key__pt, const flea_u8_t *der_key__pcu8, flea_al_u16_t der_key_len__alu16);

# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
