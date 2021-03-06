/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


#ifndef _flea_tls_ciph_suite__H_
#define _flea_tls_ciph_suite__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/mac.h"
#include "flea/block_cipher.h"
#include "flea/ae.h"
#include "flea/tls.h"
#include "flea/pk_signer.h"
#include "internal/common/tls/tls_key_usage.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS

# define FLEA_TLS_CS_AUTH_MASK__RSA   0x01
# define FLEA_TLS_CS_AUTH_MASK__ECDSA 0x02
# define FLEA_TLS_CS_AUTH_MASK__PSK   0x04

# define FLEA_TLS_CS_KEX_MASK__ECDHE  0x08
# define FLEA_TLS_CS_KEX_MASK__RSA    0x10
# define FLEA_TLS_CS_KEX_MASK__PSK    0x20

typedef enum
{
  FLEA_TLS_PRF_SHA256
} flea_tls__prf_algorithm_t;


# define  FLEA_TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00FF

# define FLEA_TLS_NO_CIPHER                      0
# define FLEA_TLS_AE_CIPHER(raw)       ((1 << 7) | raw)
# define FLEA_TLS_BLOCK_CIPHER(raw)    (raw)
# define FLEA_TLS_IS_AE_CIPHER(enc)    ((1 << 7) & enc)
# define FLEA_TLS_IS_BLOCK_CIPHER(enc) (!((1 << 7) & enc))
# define FLEA_TLS_CIPHER_RAW_ID(enc)   (enc & 0x7F)

typedef enum
{
  FLEA_TLS_KEX_RSA,
  FLEA_TLS_KEX_ECDHE,
  FLEA_TLS_KEX_PSK,
} flea_tls__kex_method_t;

typedef struct
{
  flea_tls_cipher_suite_id_t id;

  flea_u8_t                  cipher;

  flea_u8_t                  block_size;

  flea_u8_t                  iv_size;
  flea_u8_t                  enc_key_size;
  flea_u8_t                  mac_key_size;
  flea_u8_t                  mac_size;
  flea_hash_id_e             hash_algorithm;
  flea_u8_t                  mask;
} flea_tls__cipher_suite_t;


flea_err_e THR_flea_tls_get_cipher_suite_by_id(
  flea_tls_cipher_suite_id_t       id,
  const flea_tls__cipher_suite_t** result__pt
);

const flea_tls__cipher_suite_t* flea_tls_get_cipher_suite_by_id(flea_tls_cipher_suite_id_t id__t);

flea_bool_t flea_tls__does_priv_key_type_fit_to_ciphersuite(
  flea_tls_cipher_suite_id_t id__t,
  flea_pk_key_type_e         key_type__e
);

flea_hash_id_e flea_tls_get_prf_hash_by_cipher_suite_id(flea_tls_cipher_suite_id_t id__t);

flea_tls__kex_method_t flea_tls_get_kex_method_by_cipher_suite_id(flea_tls_cipher_suite_id_t id__t);

flea_tls_kex_e flea_tls__get_kex_and_auth_method_by_cipher_suite_id(flea_tls_cipher_suite_id_t id__t);

flea_err_e THR_flea_tls_get_key_block_len_from_cipher_suite_id(
  flea_tls_cipher_suite_id_t id,
  flea_al_u16_t*             result_key_block_len__palu16
);

#endif // ifdef FLEA_HAVE_TLS
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
