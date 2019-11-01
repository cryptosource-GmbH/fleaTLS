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

#ifndef _flea_byte_vec_int__H_
#define _flea_byte_vec_int__H_

#include "flea/byte_vec.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Sets the contents of the byte vector from src using the the external
 * memory. Thus the vector becomes a reference.
 */
void flea_byte_vec_t__copy_content_set_ref_use_mem(
  flea_byte_vec_t*       trgt,
  flea_u8_t*             trgt_mem,
  const flea_byte_vec_t* src
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
