/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_types_int__H_
#define _flea_types_int__H_

#include "internal/common/default.h"

#if FLEA_WORD_BIT_SIZE == 32

/**
 * Half unsigned machine word.
 */
typedef flea_u16_t flea_hlf_uword_t;

/**
 * Half signed machine word.
 */
typedef flea_s16_t flea_hlf_sword_t;

/**
 * Unsigned machine word.
 */
typedef flea_u32_t flea_uword_t;

/**
 * Signed machine word.
 */
typedef flea_s32_t flea_sword_t;

/**
 * Double unsigned machine word.
 */
typedef flea_u64_t flea_dbl_uword_t;

/**
 * Double signed machine word.
 */
typedef flea_s64_t flea_dbl_sword_t;
# define FLEA_LOG2_WORD_BIT_SIZE 5

#elif FLEA_WORD_BIT_SIZE == 16

/**
 * Half unsigned machine word.
 */
typedef flea_u8_t flea_hlf_uword_t;

/**
 * Half signed machine word.
 */
typedef flea_s8_t flea_hlf_sword_t;

/**
 * Unsigned machine word.
 */
typedef flea_u16_t flea_uword_t;

/**
 * Signed machine word.
 */
typedef flea_s16_t flea_sword_t;

/**
 * Double unsigned machine word.
 */
typedef flea_u32_t flea_dbl_uword_t;

/**
 * Double signed machine word.
 */
typedef flea_s32_t flea_dbl_sword_t;
# define FLEA_LOG2_WORD_BIT_SIZE 4

#elif FLEA_WORD_BIT_SIZE == 8

/**
 * Half unsigned machine word.
 */
typedef flea_u8_t flea_hlf_uword_t;

/**
 * Half signed machine word.
 */
typedef flea_s8_t flea_hlf_sword_t;

/**
 * Unsigned machine word.
 */
typedef flea_u16_t flea_uword_t;

/**
 * Signed machine word.
 */
typedef flea_s16_t flea_sword_t;

/**
 * Double unsigned machine word.
 */
typedef flea_u32_t flea_dbl_uword_t;

/**
 * Double signed machine word.
 */
typedef flea_s32_t flea_dbl_sword_t;

# define FLEA_LOG2_WORD_BIT_SIZE 3

#else // if FLEA_WORD_BIT_SIZE == 32
# error invalid value of FLEA_WORD_BIT_SIZE
#endif // if FLEA_WORD_BIT_SIZE == 32

#define FLEA_UWORD_MAX     ((flea_uword_t) (-1))
#define FLEA_HLF_UWORD_MAX ((flea_hlf_uword_t) (-1))

/**
 * Unsigned byte length of mpis
 */
typedef flea_u16_t flea_mpi_ulen_t;

/**
 * Signed byte length of mpis
 */
typedef flea_s16_t flea_mpi_slen_t;

/**
 * Unsigned bit lengths of mpis
 */
typedef flea_u16_t flea_mpi_ubil_t;

/**
 * Signed bit lengths of mpis
 */
typedef flea_s16_t flea_mpi_sbil_t;

/**
 * Type holding data lengths. Can be switched from 32 bit to 16 bit.
 */

#endif /* h-guard */
