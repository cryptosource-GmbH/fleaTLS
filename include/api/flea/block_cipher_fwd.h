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


#ifndef _flea_block_cipher_fwd__H_
#define _flea_block_cipher_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Forward declaration.
 */
struct struct_flea_ecb_mode_ctx_t;

/**
 * \struct flea_ecb_mode_ctx_t
 *  ECB block cipher mode context type the function of which are defined in
 *  block_cipher.h.
 */
typedef struct struct_flea_ecb_mode_ctx_t flea_ecb_mode_ctx_t;


/**
 * Forward declaration.
 */
struct struct_flea_ctr_mode_ctx_t;

/**
 * \struct flea_ctr_mode_ctx_t
 *  CTR block cipher mode context type the function of which are defined in
 *  block_cipher.h.
 */
typedef struct struct_flea_ctr_mode_ctx_t flea_ctr_mode_ctx_t;

/**
 * Forward declaration.
 */
struct struct_flea_cbc_mode_ctx_t;

/**
 * \struct flea_cbc_mode_ctx_t
 *  CBC block cipher mode context type the function of which are defined in
 *  block_cipher.h.
 */
typedef struct struct_flea_cbc_mode_ctx_t flea_cbc_mode_ctx_t;

/**
 * supported block ciphers.
 */
typedef enum { flea_des_single = 1, flea_tdes_2key = 2, flea_tdes_3key = 3, flea_desx = 4, flea_aes128 = 5,
               flea_aes192     = 6,
               flea_aes256     = 7 } flea_block_cipher_id_e;

/**
 * General cipher prossing direction.
 */
typedef enum { flea_encrypt, flea_decrypt } flea_cipher_dir_e;

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
