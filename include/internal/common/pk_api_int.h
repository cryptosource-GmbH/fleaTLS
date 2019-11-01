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

#include "flea/byte_vec.h"
#include "flea/pubkey.h"

#ifndef _flea_pk_api_int__H_
# define _flea_pk_api_int__H_


# ifdef FLEA_HAVE_ASYM_ALGS

#  define FLEA_PK_GET_PRIMITIVE_ID_FROM_SCHEME_ID(x) ((x >> FLEA_PK_ID_OFFS_PRIMITIVE) << FLEA_PK_ID_OFFS_PRIMITIVE)
#  define FLEA_PK_GET_ENCODING_ID_FROM_SCHEME_ID(x)  (x & ((1 << FLEA_PK_ID_OFFS_PRIMITIVE) - 1))

flea_err_e THR_flea_pk_api__enc_msg_ansi_x9_62(
  flea_u8_t*     input_output,
  flea_al_u16_t  input_len,
  flea_al_u16_t* output_len,
  flea_al_u16_t  bit_size
);


/**
 *  Encrypt a message using a public key scheme.
 *  @param id ID of the encryption scheme to use
 *  @param hash_id ID of the hash scheme to use (if applicable)
 *  @param message the message to be encrypted
 *  @param message_len the length of message
 *  @param result buffer to store the ciphertext
 *  number of bytes written to result
 *  @param key the public key to use for the encryption
 *  @param key_len the length of key
 *  @param params public parameters associated with the key
 *  @param params_len the length of params
 */
flea_err_e THR_flea_pk_api__encrypt_message(
  flea_pk_scheme_id_e id,
  flea_hash_id_e      hash_id,
  const flea_u8_t*    message,
  flea_al_u16_t       message_len,
  flea_byte_vec_t*    result,
  const flea_u8_t*    key,
  flea_al_u16_t       key_len,
  const flea_u8_t*    params,
  flea_al_u16_t       params_len
);

# endif // ifdef FLEA_HAVE_ASYM_ALGS

#endif /* h-guard */
