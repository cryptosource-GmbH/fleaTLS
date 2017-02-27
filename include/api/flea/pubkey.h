/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pubkey__H_
#define _flea_pubkey__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "flea/x509.h"
#include "flea/ec_gfp_dom_par.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_PK_ID_OFFS_PRIMITIVE 4

/**
 * Supported encryption and signature public key primitives.
 */
typedef enum
{
  flea_rsa_sign   = 0 << FLEA_PK_ID_OFFS_PRIMITIVE,
    flea_rsa_encr = 1 << FLEA_PK_ID_OFFS_PRIMITIVE,
    flea_ecdsa    = 2 << FLEA_PK_ID_OFFS_PRIMITIVE
} flea_pk_primitive_id_t;

/**
 * Supported public key encoding schemes.
 */
typedef enum { flea_emsa1 = 0, flea_pkcs1_v1_5 = 1, flea_oaep = 2 } flea_pk_encoding_id_t;

/**
 * Supported public key encryption and signature configurations.
 */
typedef enum
{
  flea_ecdsa_emsa1         = flea_ecdsa | flea_emsa1,
  flea_rsa_oaep_encr       = flea_rsa_encr | flea_oaep,
  flea_rsa_pkcs1_v1_5_encr = flea_rsa_encr | flea_pkcs1_v1_5,
  flea_rsa_pkcs1_v1_5_sign = flea_rsa_sign | flea_pkcs1_v1_5,
} flea_pk_scheme_id_t;

typedef enum { flea_ecc_key, flea_rsa_key } flea_pk_key_type_t;

# ifdef FLEA_HAVE_ECC

typedef struct
{
  flea_byte_vec_t           public_point_encoded__rcu8;
  flea_ec_gfp_dom_par_ref_t dp__t;
#  ifdef FLEA_USE_STACK_BUF
  flea_u8_t                 dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t                 pub_point__mem__bu8[FLEA_ECC_MAX_ENCODED_POINT_LEN];
#  else
  flea_u8_t*                dp_mem__bu8;
  flea_u8_t*                pub_point__mem__bu8;
#  endif
} flea_ec_pubkey_val_t;
# endif /* #ifdef FLEA_HAVE_ECC */

# ifdef FLEA_HAVE_RSA

typedef struct
{
  flea_ref_cu8_t mod__rcu8;
  flea_ref_cu8_t pub_exp__rcu8;
#  ifdef FLEA_USE_STACK_BUF
  flea_u8_t      mod_mem__bu8[FLEA_RSA_MAX_MOD_BYTE_LEN];
  flea_u8_t      exp_mem__bu8[FLEA_RSA_MAX_PUB_EXP_BYTE_LEN];
#  else
  flea_u8_t*     mod_mem__bu8;
  flea_u8_t*     exp_mem__bu8;
#  endif
} flea_rsa_pubkey_val_t;

# endif /* FLEA_HAVE_RSA */

typedef union
{
# ifdef FLEA_HAVE_RSA
  flea_rsa_pubkey_val_t rsa_public_val__t;
# endif
# ifdef FLEA_HAVE_ECC
  flea_ec_pubkey_val_t  ec_public_val__t;
# endif
} flea_public_key_val_with_params_u;

typedef struct
{
  flea_pk_key_type_t                key_type__t;
  flea_u16_t                        key_bit_size__u16;
  flea_u16_t                        primitive_input_size__u16;
  flea_public_key_val_with_params_u pubkey_with_params__u;
} flea_public_key_t;


# define flea_public_key_t__INIT_VALUE {.key_bit_size__u16 = 0}

void flea_public_key_t__dtor(flea_public_key_t* key__pt);

flea_err_t THR_flea_x509_parse_ecc_public_params(
  const flea_byte_vec_t*     encoded_parameters__pt,
  flea_ec_gfp_dom_par_ref_t* dom_par__pt
);

/*flea_err_t THR_flea_x509_parse_rsa_public_key(
 * const flea_byte_vec_t* public_key_value__pt,
 * flea_byte_vec_t*       modulus__pt,
 * flea_byte_vec_t*       pub_exp__pt
 * );*/

/*
 * flea_err_t THR_flea_public_key_t__ctor(
 * flea_public_key_t*    key__pt,
 * flea_pk_key_type_t    key_type,
 * const flea_byte_vec_t* key_as_bit_string_tlv__prcu8,
 * const flea_byte_vec_t* encoded_params__prcu8
 * );*/
flea_err_t THR_flea_public_key_t__ctor_asn1(
  flea_public_key_t*     key__pt,
  const flea_byte_vec_t* key_as_bit_string_tlv__prcu8,
  const flea_byte_vec_t* encoded_params__prcu8,
  const flea_byte_vec_t* alg_oid__pt
);

/*
 * flea_err_t THR_flea_public_key_t__ctor(
 * flea_public_key_t*     key__pt,
 * flea_pk_key_type_t     key_type,
 * const flea_byte_vec_t* key_as_bit_string_tlv__prcu8,
 * const flea_byte_vec_t* encoded_params__prcu8
 * );*/

flea_err_t THR_flea_public_key_t__ctor_cert(
  flea_public_key_t*          key__pt,
  const flea_x509_cert_ref_t* cert_ref__pt
);

flea_err_t THR_flea_x509_get_hash_id_and_key_type_from_oid(
  const flea_u8_t*    oid__pcu8,
  flea_al_u16_t       oid_len__alu16,
  flea_hash_id_t*     result_hash_id__pe,
  flea_pk_key_type_t* result_key_type_e
);


flea_err_t THR_flea_public_key_t__verify_signature(
  const flea_public_key_t* key__pt,
  flea_pk_scheme_id_t      pk_scheme_id__t,
  const flea_byte_vec_t*   message__prcu8,
  const flea_byte_vec_t*   signature__prcu8,
  flea_hash_id_t           hash_id__t
);

flea_err_t THR_flea_public_key_t__verify_signature_use_sigalg_id(
  const flea_public_key_t*     public_key__pt,
  const flea_x509_algid_ref_t* sigalg_id__t,
  const flea_byte_vec_t*       tbs_data__pt,
  const flea_byte_vec_t*       signature__pt
);

flea_err_t THR_flea_public_key_t__encrypt_message(
  const flea_public_key_t* key__pt,
  flea_pk_scheme_id_t      pk_scheme_id__t,
  flea_hash_id_t           hash_id__t,
  const flea_u8_t*         message__pcu8,
  flea_al_u16_t            message_len__alu16,
  flea_byte_vec_t*         result__pt
);

/*
 * flea_err_t THR_flea_public_key_t__encrypt_message(
 * const flea_public_key_t* key__pt,
 * flea_pk_scheme_id_t      pk_scheme_id__t,
 * flea_hash_id_t           hash_id__t,
 * const flea_u8_t*         message__pcu8,
 * flea_al_u16_t            message_len__alu16,
 * flea_u8_t*               result__pu8,
 * flea_al_u16_t*           result_len__palu16
 * );*/

flea_err_t THR_flea_public_key_t__ctor_rsa(
  flea_public_key_t*    key__pt,
  const flea_ref_cu8_t* mod__pcrcu8,
  const flea_ref_cu8_t* pub_exp__pcrcu8

  /*const flea_byte_vec_t* mod__pcrcu8,
   * const flea_byte_vec_t* pub_exp__pcrcu8*/
);

flea_err_t THR_flea_public_key_t__ctor_ecc(
  flea_public_key_t*               key__pt,
  const flea_byte_vec_t*           public_key_value__pt,
  const flea_ec_gfp_dom_par_ref_t* dp__pt
);


# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
