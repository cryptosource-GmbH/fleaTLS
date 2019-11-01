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


#ifndef __types_H_
#define __types_H_

#include "internal/common/default.h"
#include "flea/error.h"
#include "internal/common/types_int.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Integer representing a boolean value.
 */
typedef flea_al_u8_t flea_bool_t;

#define FLEA_FALSE 0
#define FLEA_TRUE  1

/**
 * Integer representing data lengths. Is used throughout the fleaTLS API.
 */
#ifdef FLEA_HAVE_DTL_32BIT

typedef flea_u32_t flea_dtl_t;
#else

typedef flea_u16_t flea_dtl_t;
#endif

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
