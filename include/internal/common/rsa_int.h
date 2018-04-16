/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

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
