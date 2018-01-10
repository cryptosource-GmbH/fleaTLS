/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pubkey_int__H_
#define _flea_pubkey_int__H_

#include "internal/common/default.h"
#include "flea/byte_vec.h"
#include "flea/hash.h"
#include "flea/pubkey.h"
#include "flea/ec_dom_par.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_ref_cu8_t mod__rcu8;
  flea_ref_cu8_t pub_exp__rcu8;
#ifdef FLEA_STACK_MODE
  flea_u8_t      mod_mem__bu8[FLEA_RSA_MAX_MOD_BYTE_LEN];
  flea_u8_t      exp_mem__bu8[FLEA_RSA_MAX_PUB_EXP_BYTE_LEN];
#else
  flea_u8_t*     mod_mem__bu8;
  flea_u8_t*     exp_mem__bu8;
#endif // ifdef FLEA_STACK_MODE
} flea_rsa_pubkey_val_t;

#ifdef FLEA_HAVE_RSA
flea_err_e THR_get_hash_id_from_x509_id_for_rsa(
  flea_u8_t       cert_id__u8,
  flea_hash_id_e* result__pt
);


flea_err_e THR_flea_x509_parse_rsa_public_key(
  const flea_byte_vec_t* public_key_value__pt,
  flea_ref_cu8_t*        modulus__pt,
  flea_ref_cu8_t*        pub_exp__pt
);

flea_err_e THR_flea_public_key_t__create_rsa_key(
  flea_rsa_pubkey_val_t* key__pt,
  const flea_ref_cu8_t*  mod__pcrcu8,
  const flea_ref_cu8_t*  exp__pcrcu8
);
#endif // ifdef FLEA_HAVE_RSA


#ifdef FLEA_HAVE_ECC
extern const flea_u8_t ecdsa_oid_prefix__acu8[6];

typedef struct
{
  flea_byte_vec_t       public_point_encoded__rcu8;
  flea_ec_dom_par_ref_t dp__t;
# ifdef FLEA_STACK_MODE
  flea_u8_t             dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t             pub_point__mem__bu8[FLEA_ECC_MAX_ENCODED_POINT_LEN];
# else
  flea_u8_t*            dp_mem__bu8;
  flea_u8_t*            pub_point__mem__bu8;
# endif // ifdef FLEA_STACK_MODE
} flea_ec_pubkey_val_t;

flea_err_e THR_get_hash_id_from_x509_id_for_ecdsa(
  const flea_u8_t cert_id__pcu8[2],
  flea_hash_id_e* result__pt
);

/* assumes that result__pu8 has sufficient length allocated */
flea_err_e THR_flea_x509_decode_ecdsa_signature(
  flea_u8_t*             result__pu8,
  flea_al_u16_t*         result_len__palu16,
  const flea_byte_vec_t* x509_enc_sig__pt
);

flea_err_e THR_flea_public_key_t__create_ecdsa_key(
  flea_ec_pubkey_val_t*        ecc_key__pt,
  const flea_byte_vec_t*       public_point_encoded__pcrcu8,
  const flea_ec_dom_par_ref_t* dp_ref__pt
);

flea_err_e THR_flea_x509_parse_ecc_public_params(
  const flea_byte_vec_t* encoded_parameters__pt,
  flea_ec_dom_par_ref_t* dom_par__pt
);

#endif // ifdef FLEA_HAVE_ECC
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
