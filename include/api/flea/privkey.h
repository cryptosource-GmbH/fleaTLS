/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_privkey__H_
#define _flea_privkey__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "flea/x509.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/pubkey.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif


typedef struct
{
  flea_ec_gfp_dom_par_ref_t dp__t;
  flea_ref_cu8_t            scalar__rcu8;
# ifdef FLEA_USE_STACK_BUF
  flea_u8_t                 dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t                 priv_scalar__mem__bu8[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
# else
  flea_u8_t                 *dp_mem__bu8;
  flea_u8_t                 *priv_scalar__mem__bu8;
# endif
} flea_ec_privkey_val_t;

typedef struct
{
  flea_ref_cu8_t pqd1d2c__rcu8 [5];
# ifdef FLEA_USE_STACK_BUF
  flea_u8_t      priv_key_mem__bu8 [FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE];
# else
  flea_u8_t      *priv_key_mem__bu8;
# endif
} flea_rsa_privkey_val_t;

typedef struct
{
  flea_pk_key_type_t key_type__t;
  flea_u16_t         key_bit_size__u16;
  flea_u16_t         max_primitive_input_len__u16;
  union
  {
    flea_rsa_privkey_val_t rsa_priv_key_val__t;
    flea_ec_privkey_val_t  ec_priv_key_val__t;
  } privkey_with_params__u;
} flea_private_key_t;

# define flea_private_key_t__INIT_VALUE { .key_bit_size__u16 = 0 }

void
flea_private_key_t__dtor(flea_private_key_t *privkey__pt);

flea_err_t
THR_flea_rsa_raw_operation_crt_private_key(
  const flea_private_key_t *priv_key__pt,
  flea_u8_t                *result_enc,
  const flea_u8_t          *base_enc,
  flea_al_u16_t            base_length);

flea_err_t
THR_flea_private_key_t__ctor_rsa_internal_format(flea_private_key_t *key__pt, const flea_ref_cu8_t *priv_key_enc_internal_format__prcu8, flea_al_u16_t key_bit_size__alu16);

flea_err_t
THR_flea_private_key_t__ctor_rsa_components(
  flea_private_key_t *key__pt,
  flea_al_u16_t      key_bit_size__alu16,
  const flea_u8_t    *p__pcu8,
  flea_al_u16_t      p_len__alu16,
  const flea_u8_t    *q__pcu8,
  flea_al_u16_t      q_len__alu16,
  const flea_u8_t    *d1__pcu8,
  flea_al_u16_t      d1_len__alu16,
  const flea_u8_t    *d2__pcu8,
  flea_al_u16_t      d2_len__alu16,
  const flea_u8_t    *c__pcu8,
  flea_al_u16_t      c_len__alu16
);

flea_err_t
THR_flea_private_key_t__ctor_ecc(flea_private_key_t *key__pt, const flea_ref_cu8_t *scalar__cprcu8, const flea_ec_gfp_dom_par_ref_t *dp_ref__pt);

#endif /* h-guard */
#ifdef __cplusplus
}
#endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */
