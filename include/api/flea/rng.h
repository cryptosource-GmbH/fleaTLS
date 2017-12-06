/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef __flea_rng_H_
#define __flea_rng_H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function for accessing the static RNG of the flea library.
 */


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
 * THR_flea_lib__init().
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
