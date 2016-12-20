/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_privkey__H_
#define _flea_privkey__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "flea/x509.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/pubkey.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct
{
  flea_ec_gfp_dom_par_ref_t dp__t;
  flea_ref_cu8_t scalar__rcu8;
#ifdef FLEA_USE_STACK_BUF
  flea_u8_t dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t priv_scalar__mem__bu8[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
#else
  flea_u8_t *dp_mem__bu8;
  flea_u8_t *priv_scalar__mem__bu8;
#endif 
} flea_ec_privkey_val_t;

typedef struct 
{
   flea_ref_cu8_t p__rcu8;
   flea_ref_cu8_t q__rcu8;
   flea_ref_cu8_t d1__rcu8;
   flea_ref_cu8_t d2__rcu8;
   flea_ref_cu8_t c__rcu8;
#ifdef FLEA_USE_STACK_BUF
   flea_u8_t priv_key_mem__bu8 [FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE];
#else
   flea_u8_t *priv_key_mem__bu8;
#endif

} flea_rsa_privkey_val_t;

typedef struct {

  flea_pk_key_type_t key_type__t;
  flea_u16_t key_bit_size__u16;
  union 
  {
    flea_rsa_privkey_val_t rsa_priv_key_val__t;
    flea_ec_privkey_val_t  ec_priv_key_val__t; 
  } privkey_with_params__u;
    

} flea_private_key_t;



#endif /* h-guard */
#ifdef __cplusplus
}
#endif
