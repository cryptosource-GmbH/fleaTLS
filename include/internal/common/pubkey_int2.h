/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pubkey_int2__H_
# define _flea_pubkey_int2__H_

# include "flea/pubkey.h"

# ifdef __cplusplus
extern "C" {
# endif


flea_err_e THR_flea_pk_ensure_key_strength(
  flea_pk_sec_lev_e  required_strength__e,
  flea_al_u16_t      key_bit_size__alu16,
  flea_pk_key_type_e key_type
);


flea_pk_sec_lev_e flea_pk_sec_lev_from_bit_mask(flea_al_u8_t bit_mask__alu8);

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
