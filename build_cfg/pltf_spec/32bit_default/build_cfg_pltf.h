/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_build_cfg_pltf__H_
#define _flea_build_cfg_pltf__H_


#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char flea_u8_t;
typedef signed char flea_s8_t;
typedef unsigned short flea_u16_t;
typedef short flea_s16_t;
typedef unsigned int flea_u32_t;
typedef int flea_s32_t;
typedef unsigned long long flea_u64_t;
typedef long long flea_s64_t;


/* "at least" width types */
typedef flea_u32_t flea_al_u8_t;
typedef flea_s32_t flea_al_s8_t;
typedef flea_u32_t flea_al_u16_t;
typedef flea_s32_t flea_al_s16_t;

/**
 * Can be either 16 or 32
 */
#define FLEA_WORD_BIT_SIZE 32 // FBFLAGS__INT_LIST 16 32
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
