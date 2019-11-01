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

#include "flea/kdf.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"

flea_err_e THR_flea_kdf_X9_63(
  flea_hash_id_e   id__t,
  const flea_u8_t* input__pcu8,
  flea_al_u16_t    input_len__alu16,
  const flea_u8_t* shared_info__pcu8,
  flea_al_u16_t    shared_info_len__alu16,
  flea_u8_t*       output__pu8,
  flea_al_u16_t    output_len__alu16
)
{
  flea_hash_ctx_t ctx__t;
  flea_u8_t counter__au8[4] = {0, 0, 0, 1};
  flea_al_u8_t hash_out_len__alu8;
  flea_al_u16_t nb_full_blocks__alu16, i;

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx__t);
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx__t, id__t));
  hash_out_len__alu8    = flea_hash_ctx_t__get_output_length(&ctx__t);
  nb_full_blocks__alu16 = output_len__alu16 / hash_out_len__alu8;
  for(i = 0; i < nb_full_blocks__alu16; i++)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, input__pcu8, input_len__alu16));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, &counter__au8[0], sizeof(counter__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, shared_info__pcu8, shared_info_len__alu16));
    FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx__t, output__pu8));
    output__pu8       += hash_out_len__alu8;
    output_len__alu16 -= hash_out_len__alu8;
    flea_hash_ctx_t__reset(&ctx__t);
    flea__increment_encoded_BE_int(counter__au8, sizeof(counter__au8));
  }
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, input__pcu8, input_len__alu16));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, &counter__au8[0], sizeof(counter__au8)));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, shared_info__pcu8, shared_info_len__alu16));
  FLEA_CCALL(THR_flea_hash_ctx_t__final_with_length_limit(&ctx__t, output__pu8, output_len__alu16));

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx__t);
  );
}
