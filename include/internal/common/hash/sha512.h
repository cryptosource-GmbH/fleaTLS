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


#ifndef _flea_sha512__H_
#define _flea_sha512__H_

#include "flea/types.h"

#include "flea/hash.h"

void flea_sha512_encode_hash_state(
  const flea_hash_ctx_t* ctx__pt,
  flea_u8_t*             output,
  flea_al_u8_t           output_len
);

void flea_sha512_init(flea_hash_ctx_t* ctx__pt);

void flea_sha384_init(flea_hash_ctx_t* ctx__pt);

flea_err_e THR_flea_sha512_compression_function(
  flea_hash_ctx_t* ctx__pt,
  const flea_u8_t* input
) FLEA_ATTRIB_UNUSED_RESULT;

#endif /* h-guard */
