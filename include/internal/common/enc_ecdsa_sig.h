/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_enc_ecdsa_sig__H_
#define _flea_enc_ecdsa_sig__H_

#include "flea/types.h"
#include "flea/byte_vec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * append the signature to result__pt
 */
flea_err_e THR_flea_asn1_encode_ecdsa_sig(
  const flea_u8_t* r__pcu8,
  flea_al_u8_t     r_len__alu8,
  const flea_u8_t* s__pcu8,
  flea_al_u8_t     s_len__alu8,
  flea_byte_vec_t* result__pt
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
