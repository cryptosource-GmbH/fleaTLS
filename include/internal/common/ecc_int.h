/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ecc_int__H_
#define _flea_ecc_int__H_
#include "internal/common/default.h"

/**
 * According to Hasse's theorem, the base point order can be larger than p by
 * one bit
 */
#define FLEA_ECC_MAX_ORDER_BIT_SIZE (FLEA_ECC_MAX_MOD_BIT_SIZE + 1)

#define FLEA_ECC_MAX_MOD_BYTE_SIZE FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_MOD_BIT_SIZE)
#define FLEA_ECC_MAX_MOD_WORD_SIZE FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_ECC_MAX_MOD_BYTE_SIZE)

#define FLEA_ECC_MAX_ORDER_BYTE_SIZE FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_ORDER_BIT_SIZE)
#define FLEA_ECC_MAX_ORDER_WORD_SIZE FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_ECC_MAX_ORDER_BYTE_SIZE)

#endif /* h-guard */
