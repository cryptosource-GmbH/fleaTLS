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

#ifndef _flea_rsa_int__H_
#define _flea_rsa_int__H_


#ifdef __cplusplus
extern "C" {
#endif


/**
 * number of words by which the larger prime in CRT-RSA may become larger than
 * the number of words in the half modulus length. (with a PQ-diff of x, one
 * prime is longer by x/2 bits, the other shorter by x/2 bits than the half
 * bit length of the modulus.
 */
#define FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF FLEA_CEIL_WORD_LEN_FROM_BIT_LEN(FLEA_RSA_CRT_PQ_BIT_DIFF / 2)

#define FLEA_MPI_DIV_VN_HLFW_LEN_FOR_RSA_CRT_REDUCTIONS \
  FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN( \
    FLEA_RSA_CRT_MAX_PRIME_WORD_LEN \
  )
#define FLEA_MPI_DIV_UN_HLFW_LEN_FOR_RSA_CRT_REDUCTIONS \
  FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN( \
    2 * FLEA_RSA_CRT_MAX_PRIME_WORD_LEN \
  )

#define FLEA_MPI_DIV_VN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS \
  FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN( \
    FLEA_RSA_SF_MAX_MOD_WORD_LEN \
  )
#define FLEA_MPI_DIV_UN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS \
  FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN( \
    2 * FLEA_RSA_SF_MAX_MOD_WORD_LEN \
  )

#define FLEA_RSA_CRT_MAX_PRIME_WORD_LEN \
  (((FLEA_RSA_MAX_KEY_BIT_SIZE / 2) + (FLEA_RSA_CRT_PQ_BIT_DIFF) \
  / 2 + FLEA_WORD_BIT_SIZE - 1) / FLEA_WORD_BIT_SIZE)

#define FLEA_RSA_SF_MAX_MOD_WORD_LEN \
  ((FLEA_RSA_MAX_KEY_BIT_SIZE + FLEA_WORD_BIT_SIZE - 1) \
  / FLEA_WORD_BIT_SIZE)

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
