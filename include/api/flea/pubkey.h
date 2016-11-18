/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pubkey__H_
#define _flea_pubkey__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
//#include "internal/common/pk_api_int.h"
#include "flea/ec_gfp_dom_par.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_PK_ID_OFFS_PRIMITIVE 4
/**
 * Supported encryption and signature public key primitives.
 */
typedef enum
{
  flea_rsa_sign = 0 << FLEA_PK_ID_OFFS_PRIMITIVE,
  flea_rsa_encr = 1 << FLEA_PK_ID_OFFS_PRIMITIVE,
  flea_ecdsa = 2 << FLEA_PK_ID_OFFS_PRIMITIVE
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
  flea_ecdsa_emsa1 = flea_ecdsa | flea_emsa1,
  flea_rsa_oaep_encr = flea_rsa_encr | flea_oaep,
  flea_rsa_pkcs1_v1_5_encr = flea_rsa_encr | flea_pkcs1_v1_5,
  flea_rsa_pkcs1_v1_5_sign = flea_rsa_sign | flea_pkcs1_v1_5,
} flea_pk_scheme_id_t;

//typedef enum { flea_rsa_key, flea_ecc_key } flea_pub_key_type_t;
  typedef enum { flea_ecc_key, flea_rsa_key } flea_pk_key_type_t;

  // TODO: make internal:
#ifdef FLEA_HAVE_ECC
typedef struct
{

  flea_ref_cu8_t public_point_encoded__rcu8; 
  flea_ec_gfp_dom_par_ref_t dp__t;
#ifdef FLEA_USE_STACK_BUF
  flea_u8_t dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t pub_point__mem__bu8[FLEA_ECC_MAX_PUBKEY_LEN];
#else
  flea_u8_t *dp_mem__bu8;
  flea_u8_t *pub_point__mem__bu8;
#endif 
} flea_ec_pubkey_val_t;
#endif /* #ifdef FLEA_HAVE_ECC */

#ifdef FLEA_HAVE_RSA
typedef struct
{
  flea_ref_cu8_t mod__rcu8;
  flea_ref_cu8_t pub_exp__rcu8;
#ifdef FLEA_USE_STACK_BUF
  flea_u8_t mod_mem__bu8[FLEA_RSA_MAX_MOD_BYTE_LEN];
  flea_u8_t exp_mem__bu8[FLEA_RSA_MAX_PUB_EXP_BYTE_LEN];
#else
  flea_u8_t *mod_mem__bu8;
  flea_u8_t *exp_mem__bu8;
#endif 
} flea_rsa_pubkey_val_t;

#endif /* FLEA_HAVE_RSA */

typedef union
{
#ifdef FLEA_HAVE_RSA
  flea_rsa_pubkey_val_t rsa_public_val__t;
#endif
#ifdef FLEA_HAVE_ECC
  flea_ec_pubkey_val_t ec_public_val__t;
#endif
} flea_public_key_val_with_params_u;

typedef struct 
{
  flea_pk_key_type_t key_type__t;
  flea_u16_t key_bit_size__u16;
  flea_public_key_val_with_params_u pubkey_with_params__u;

} flea_public_key_t;

#define flea_publick_key_t__INIT_VALUE {.key_bit_size__u16 = 0 }

void flea_public_key_t__dtor(flea_public_key_t *key__pt);

flea_err_t THR_flea_x509_parse_ecc_public_params(const flea_ref_cu8_t *encoded_parameters__pt, flea_ec_gfp_dom_par_ref_t *dom_par__pt);

flea_err_t THR_flea_x509_parse_rsa_public_key(const flea_ref_cu8_t *public_key_value__pt, flea_ref_cu8_t *modulus__pt, flea_ref_cu8_t *pub_exp__pt);

flea_err_t THR_flea_public_key_t__ctor(flea_public_key_t* key__pt, flea_pk_key_type_t key_type, const flea_ref_cu8_t *key_as_bit_string_tlv__prcu8, const flea_ref_cu8_t *encoded_params__prcu8);

flea_err_t THR_flea_public_key_t__verify_signature(const flea_public_key_t *key__pt, flea_pk_scheme_id_t pk_scheme_id__t, const flea_ref_cu8_t *message__prcu8, const flea_ref_cu8_t * signature__prcu8,  flea_hash_id_t hash_id__t );

#endif /* h-guard */


#ifdef __cplusplus
}
#endif
