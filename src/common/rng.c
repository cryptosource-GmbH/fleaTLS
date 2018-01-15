/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/rng.h"
#include "internal/common/rng_int.h"
#include "flea/ctr_mode_prng.h"
#include "flea/bin_utils.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/hash.h"
#include "flea/types.h"
#include "flea/crc.h"
#include "string.h"
#include "internal/common/mutex_int.h"

/**
 * Must be an even number.
 */
#define FLEA_RNG_ENTROPY_POOL_BYTE_SIZE 16

/**
 * Threshold for the estimated pool entropy in bits at which the pool is used
 * for reseeding the global RNG.
 */
#define FLEA_RNG_ENTROPY_POOL_ENTROPY_THRESHOLD 128

static flea_ctr_mode_prng_t flea_gl_rng_ctx__t;
static flea_u8_t flea_gl_entropy_pool__au8[FLEA_RNG_ENTROPY_POOL_BYTE_SIZE];
static flea_al_u16_t flea_gl_rng_entropy_cnt__alu16    = 0;
static flea_al_u8_t flea_gl_rng_entropy_pool_pos__alu8 = 0;
static flea_al_u16_t flea_gl_rng_current_crc__alu16    = 0;

#ifdef FLEA_HAVE_MUTEX
FLEA_DECL_STATIC_MUTEX(rng_mutex__t);
static flea_u8_t rng_is_mutex_init__u8 = 0;
#endif

static flea_prng_save_f flea_gl_rng_save_mbn__f;

static flea_err_e THR_flea_rng__reseed_volatile_inner(
  const flea_u8_t* seed__pcu8,
  flea_dtl_t       seed_len__dtl
)
{
  return THR_flea_ctr_mode_prng_t__reseed(&flea_gl_rng_ctx__t, seed__pcu8, seed_len__dtl);
}

static flea_al_u16_t flea_rng_add_2bytes_to_pool(
  flea_al_u16_t     current_crc__alu16,
  const flea_u16_t* to_add__u16
)
{
  flea_al_u8_t entropy_pool_pos__alu8 = flea_gl_rng_entropy_pool_pos__alu8;

  current_crc__alu16 = flea_crc16_ccit_compute(current_crc__alu16, (const flea_u8_t*) &to_add__u16, 2);
  flea_gl_entropy_pool__au8[entropy_pool_pos__alu8]     ^= (current_crc__alu16 >> 8);
  flea_gl_entropy_pool__au8[entropy_pool_pos__alu8 + 1] ^= (current_crc__alu16 & 0xFF);
  entropy_pool_pos__alu8 += 2;
  if(entropy_pool_pos__alu8 >= sizeof(flea_gl_entropy_pool__au8))
  {
    entropy_pool_pos__alu8 = 0;
  }
  flea_gl_rng_entropy_pool_pos__alu8 = entropy_pool_pos__alu8;
  return current_crc__alu16;
}

static flea_err_e THR_flea_rng__harvest_entropy_pool()
{
  FLEA_THR_BEG_FUNC();
  if(flea_gl_rng_entropy_cnt__alu16 >= FLEA_RNG_ENTROPY_POOL_ENTROPY_THRESHOLD)
  {
    flea_gl_rng_entropy_cnt__alu16 = 0;
    FLEA_CCALL(THR_flea_rng__reseed_volatile_inner(flea_gl_entropy_pool__au8, sizeof(flea_gl_entropy_pool__au8)));
  }
  FLEA_THR_FIN_SEC_empty();
}

void flea_rng__deinit()
{
  flea_ctr_mode_prng_t__dtor(&flea_gl_rng_ctx__t);
#ifdef FLEA_HAVE_MUTEX
  if(rng_is_mutex_init__u8)
  {
    FLEA_MUTEX_DESTR(&rng_mutex__t);
  }
  rng_is_mutex_init__u8 = 0;
#endif /* ifdef FLEA_HAVE_MUTEX */
}

void flea_rng__feed_low_entropy_data_to_pool(
  flea_u16_t   entropy__u16,
  flea_al_u8_t estimated_entropy__alu8
)
{
  flea_al_u16_t current_crc__alu16 = flea_gl_rng_current_crc__alu16;
  flea_al_u16_t entropy_cnt__alu16 = flea_gl_rng_entropy_cnt__alu16;

  current_crc__alu16 = flea_rng_add_2bytes_to_pool(current_crc__alu16, &entropy__u16);
  if(entropy_cnt__alu16 < FLEA_RNG_ENTROPY_POOL_ENTROPY_THRESHOLD)
  {
    entropy_cnt__alu16 += estimated_entropy__alu8;
  }
  flea_gl_rng_entropy_cnt__alu16 = entropy_cnt__alu16;
  flea_gl_rng_current_crc__alu16 = current_crc__alu16;
}

flea_err_e THR_flea_rng__init(
  const flea_u8_t* rng_seed__pcu8,
  flea_al_u16_t    rng_seed_len__alu16,
  flea_prng_save_f prng_save__f
)
{
  flea_gl_rng_save_mbn__f = prng_save__f;
  FLEA_THR_BEG_FUNC();

#ifdef FLEA_HAVE_MUTEX
  if(THR_FLEA_MUTEX_INIT(&rng_mutex__t))
  {
    FLEA_THROW("error initializing rng mutex", FLEA_ERR_MUTEX_INIT);
  }
  rng_is_mutex_init__u8 = 1;
#endif /* ifdef FLEA_HAVE_MUTEX */
  flea_ctr_mode_prng_t__INIT(&flea_gl_rng_ctx__t);
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__ctor(&flea_gl_rng_ctx__t, NULL, 0));
  FLEA_CCALL(THR_flea_rng__reseed_persistent(rng_seed__pcu8, rng_seed_len__alu16));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_rng__reseed_persistent(
  const flea_u8_t* seed__pcu8,
  flea_dtl_t       seed_len__dtl
)
{
  FLEA_DECL_BUF(new_persistent_key__bu8, flea_u8_t, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_FLEA_MUTEX_LOCK(&rng_mutex__t));
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&flea_gl_rng_ctx__t, seed__pcu8, seed_len__dtl));
  if(flea_gl_rng_save_mbn__f != NULL)
  {
    FLEA_ALLOC_BUF(new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
    flea_ctr_mode_prng_t__randomize(&flea_gl_rng_ctx__t, new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
    FLEA_CCALL(flea_gl_rng_save_mbn__f(new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
    if(THR_FLEA_MUTEX_UNLOCK(&rng_mutex__t))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
}

flea_err_e THR_flea_rng__reseed_volatile(
  const flea_u8_t* seed__pcu8,
  flea_dtl_t       seed_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_FLEA_MUTEX_LOCK(&rng_mutex__t));
  FLEA_CCALL(THR_flea_rng__reseed_volatile_inner(seed__pcu8, seed_len__dtl));

  FLEA_THR_FIN_SEC(
    if(THR_FLEA_MUTEX_UNLOCK(&rng_mutex__t))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
}

flea_err_e THR_flea_rng__flush()
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_FLEA_MUTEX_LOCK(&rng_mutex__t));
  flea_ctr_mode_prng_t__flush(&flea_gl_rng_ctx__t);
  FLEA_THR_FIN_SEC(
    if(THR_FLEA_MUTEX_UNLOCK(&rng_mutex__t))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
}

flea_err_e THR_flea_rng__randomize_no_flush(
  flea_u8_t* mem__pu8,
  flea_dtl_t mem_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_FLEA_MUTEX_LOCK(&rng_mutex__t));
  FLEA_CCALL(THR_flea_rng__harvest_entropy_pool());
  flea_ctr_mode_prng_t__randomize_no_flush(&flea_gl_rng_ctx__t, mem__pu8, mem_len__dtl);
  FLEA_THR_FIN_SEC(
    if(THR_FLEA_MUTEX_UNLOCK(&rng_mutex__t))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
}

flea_err_e THR_flea_rng__randomize(
  flea_u8_t* mem__pu8,
  flea_dtl_t mem_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_FLEA_MUTEX_LOCK(&rng_mutex__t));
  FLEA_CCALL(THR_flea_rng__harvest_entropy_pool());
  flea_ctr_mode_prng_t__randomize_no_flush(&flea_gl_rng_ctx__t, mem__pu8, mem_len__dtl);
  FLEA_CCALL(THR_FLEA_MUTEX_UNLOCK(&rng_mutex__t));
  FLEA_CCALL(THR_flea_rng__flush());
  FLEA_THR_FIN_SEC_empty(
  );
}
