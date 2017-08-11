/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pk_key_int__H_
#define _flea_pk_key_int__H_

#include "flea/privkey.h"

#ifdef __cplusplus
extern "C" {
#endif

flea_err_t THR_flea_rsa_raw_operation_crt_private_key(
  const flea_private_key_t* priv_key__pt,
  flea_u8_t*                result_enc,
  const flea_u8_t*          base_enc,
  flea_al_u16_t             base_length
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
