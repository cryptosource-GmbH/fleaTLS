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

#ifndef _flea_pk_def__H_
#define _flea_pk_def__H_


#define FLEA_PUBKEY_STRENGTH_MASK__256 4
#define FLEA_PUBKEY_STRENGTH_MASK__192 3
#define FLEA_PUBKEY_STRENGTH_MASK__128 2
#define FLEA_PUBKEY_STRENGTH_MASK__112 1
#define FLEA_PUBKEY_STRENGTH_MASK__80  0
#define FLEA_PUBKEY_STRENGTH_MASK__0   5

#define FLEA_X509_FLAGS_SEC_LEVEL_OFFS 0
#define FLEA_TLS_FLAGS_SEC_LEVEL_OFFS  7

#define FLEA_SEC_LEV_MASK              ((1 << 3) - 1)

#define FLEA_PK_SEC_LEV_BIT_MASK_FROM_X509_FLAGS(flags) \
  ((flags >> FLEA_X509_FLAGS_SEC_LEVEL_OFFS) \
  & (FLEA_SEC_LEV_MASK))
#define FLEA_PK_SEC_LEV_BIT_MASK_FROM_TLS_FLAGS(flags) ((flags >> FLEA_TLS_FLAGS_SEC_LEVEL_OFFS) & (FLEA_SEC_LEV_MASK))

#endif /* h-guard */
