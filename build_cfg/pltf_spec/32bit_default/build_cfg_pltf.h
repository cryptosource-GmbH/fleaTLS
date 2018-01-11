/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

/**
 * @file build_cfg_pltf.h
 *
 * This file specifies the type definitions for 32-bit and 64-bit standard
 * platforms.
 *
 * In order to use a 16-bit platform, provide appropriate definitions
 * here and set the correct value of FLEA_WORD_BIT_SIZE.
 */

#ifndef _flea_build_cfg_pltf__H_
#define _flea_build_cfg_pltf__H_


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Unsigned 8-bit type.
 */
typedef unsigned char flea_u8_t;

/**
 * Signed 8-bit type.
 */
typedef signed char flea_s8_t;

/**
 * Unsigned 16-bit type.
 */
typedef unsigned short flea_u16_t;

/**
 * Signed 16-bit type.
 */
typedef short flea_s16_t;

/**
 * Unsigned 32-bit type.
 */
typedef unsigned int flea_u32_t;

/**
 * Signed 32-bit type.
 */
typedef int flea_s32_t;

/**
 * Unsigned 64-bit type.
 */
typedef unsigned long long flea_u64_t;

/**
 * Signed 64-bit type.
 */
typedef long long flea_s64_t;

/**
 * An unsigned type holding at least 8 bits, otherwise it may be chosen
 * arbitrarily.
 */
typedef flea_u32_t flea_al_u8_t;

/**
 * A signed type holding at least 8 bits, otherwise it may be chosen
 * arbitrarily.
 */
typedef flea_s32_t flea_al_s8_t;

/**
 * An unsigned type holding at least 16 bits, otherwise it may be chosen
 * arbitrarily.
 */
typedef flea_u32_t flea_al_u16_t;

/**
 * A signed type holding at least 16 bits, otherwise it may be chosen
 * arbitrarily.
 */
typedef flea_s32_t flea_al_s16_t;

/**
 * The machine word bit size used in fleaTLS. Mainly determines the word size used in flea_mpi_t for public key operations. Can be either 16 or 32.
 */
#define FLEA_WORD_BIT_SIZE 32
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
