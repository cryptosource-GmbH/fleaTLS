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

#ifndef _flea_ecc_int__H_
#define _flea_ecc_int__H_
#include "internal/common/default.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * According to Hasse's theorem, the base point order can be larger than p by
 * one bit
 */
#define FLEA_ECC_MAX_ORDER_BIT_SIZE  (FLEA_ECC_MAX_MOD_BIT_SIZE + 1)

#define FLEA_ECC_MAX_MOD_BYTE_SIZE   FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_MOD_BIT_SIZE)
#define FLEA_ECC_MAX_MOD_WORD_SIZE   FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_ECC_MAX_MOD_BYTE_SIZE)

#define FLEA_ECC_MAX_ORDER_BYTE_SIZE FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_ORDER_BIT_SIZE)
#define FLEA_ECC_MAX_ORDER_WORD_SIZE FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_ECC_MAX_ORDER_BYTE_SIZE)

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
