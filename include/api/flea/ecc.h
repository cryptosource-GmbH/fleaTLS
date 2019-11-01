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

#ifndef _flea_ecc__H_
#define _flea_ecc__H_
#include "internal/common/default.h"
#include "internal/common/ecc_int.h"
#include "flea/ec_dom_par.h"

#ifdef FLEA_HAVE_ECC

/**
 * The maximal size of an uncompressed or hybrid encoded EC point.
 */
# define FLEA_ECC_MAX_UNCOMPR_POINT_SIZE (2 * (FLEA_ECC_MAX_MOD_BYTE_SIZE) +1)

/**
 * The maximal byte size of an EC private key.
 */
# define FLEA_ECC_MAX_PRIVATE_KEY_BYTE_SIZE FLEA_ECC_MAX_ORDER_BYTE_SIZE

#endif /* #ifdef FLEA_HAVE_ECC */

#endif /* h-guard */
