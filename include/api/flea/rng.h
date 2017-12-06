/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef __flea_rng_H_
#define __flea_rng_H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function for feeding low entropy value to flea's global RNG's entropy pool.
 * The function is meant only for adding of low entropy data, e.g. current
 * processor cycle
 * counts from asynchronously triggered interrupt routines. The function has a has a small and almost
 * constant timing cost.
 *
 * Note: Do not use to this function to initially seed or reseed flea's global RNG
 * with high entropy data. Other functions are avaivable for this purpose.
 *
 * @param entropy_value random value to feed to the pool
 * @param estimated_entropy the estimated entropy of entropy_value in bits
 */
void flea_rng__feed_low_entropy_data_to_pool(
  flea_u32_t   entropy_value,
  flea_al_u8_t estimated_entropy
);

/**
 * Fill a memory area with random bytes using the global RNG.
 *
 * @param mem pointer to the memory area to be randomized
 * @param mem_len the length of the area to be randomized
 *
 */
flea_err_t THR_flea_rng__randomize(
  flea_u8_t* mem,
  flea_dtl_t mem_len
);


/**
 * Reseed the global RNG state in RAM. The persistent NVM state is not affected.
 * Use this function to quickly update the RAM state without a time consuming
 * NVM-write operation.
 *
 * @param seed the seed data to be added
 * @param seed_len the length of seed
 *
 * @return flea error code
 */
flea_err_t THR_flea_rng__reseed_volatile(
  const flea_u8_t* seed,
  flea_dtl_t       seed_len
);

/**
 * Reseed the global RNG state in RAM. The persistent NVM state is also set to a
 * new value. Use this function to let high entropy seed data take a lasting
 * effect on the RNG's entropy level. Note that the persistent state will only
 * be safed if a non-null flea_prng_save_f function was provided to the function
 * THR_flea_lib__init(). Otherwise the effect of this function is the same as
 * that of THR_flea_rng__reseed_volatile().
 *
 * @param seed the seed data to be added
 * @param seed_len the length of seed
 *
 * @return flea error code
 */
flea_err_t THR_flea_rng__reseed_persistent(
  const flea_u8_t* seed,
  flea_dtl_t       seed_len
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
