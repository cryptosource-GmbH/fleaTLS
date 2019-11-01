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

#ifndef _flea_oaep__H_
#define _flea_oaep__H_

#include "flea/types.h"
#include "flea/hash.h"
#include "flea/byte_vec.h"


flea_err_e THR_flea_pk_api__enc_msg_oaep(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size__alu16,
  flea_hash_id_e hash_id__t
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_pk_api__dec_msg__oaep(
  flea_byte_vec_t* result_vec__pt,
  flea_u8_t*       input__pu8,
  flea_al_u16_t    input_len__alu16,
  flea_al_u16_t    bit_size__alu16,
  flea_hash_id_e   hash_id__t
) FLEA_ATTRIB_UNUSED_RESULT;


#endif /* h-guard */
