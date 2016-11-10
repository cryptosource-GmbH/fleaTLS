
#ifndef _flea_prng_weak_reseed__H_
#define _flea_prng_weak_reseed__H_

#include "internal/common/default.h"
#include "flea/types.h"

/**
 * must be a power of 2
 */
#define FLEA_PRNG_WEAK_RESEED_POOL_LEN 16
/**
 * must correspond to FLEA_PRNG_WEAK_RESEED_POOL_LEN 
 */
#define FLEA_PRNG_WEAK_RESEED_LOG2_POOL_LEN 4

typedef struct
{
  flea_u8_t idx__u8;
  flea_u16_t fill_idx__u16;
  //flea_u8_t pending__u8;
  //flea_u8_t have_pending__u8;
  flea_u16_t crc__u16;
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* pool__bu8;
#else
  flea_u8_t pool__bu8[FLEA_PRNG_WEAK_RESEED_POOL_LEN];
#endif
} flea_weak_reseed_ctx_t;

#define flea_weak_reseed_ctx_t__INIT_VALUE = { .pool__bu8 = NULL }
#define flea_weak_reseed_ctx_t__INIT(__p)  do { (__p)->pool__bu8 = NULL; } while(0)

flea_err_t THR_flea_weak_reseed_ctx_t__ctor(flea_weak_reseed_ctx_t* ctx__pt, flea_u16_t crc_init_val__u16);

void flea_weak_reseed_ctx_t__dtor(flea_weak_reseed_ctx_t* ctx__pt);

void flea_weak_reseed_ctx_t__reset(flea_weak_reseed_ctx_t* ctx__pt, flea_u16_t crc_init_val__u16);

void flea_weak_reseed_ctx_t__reseed(flea_weak_reseed_ctx_t* ctx__pt, const flea_u8_t* seed__pcu8, flea_al_u8_t seed_len__alu8);

#endif /* h-guard */
