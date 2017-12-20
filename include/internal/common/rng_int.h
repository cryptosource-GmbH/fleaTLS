/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_rng_int__H_
#define _flea_rng_int__H_

#include "flea/types.h"
#include "flea/lib.h"

/**
 * Function which has to be implemented for each platform. It loads the RNG
 * state from NVM, ensuring that the system will start with a secure RNG state on
 * the each start-up.
 *
 */
flea_err_e THR_flea_user__rng__load_prng_state(
  flea_u8_t*   result__bu8,
  flea_al_u8_t result_len__alu8
);

/**
 * Function which has to be implemented for each platform. It saves a new RNG
 * state in NVM, ensuring that the system will start with a secure RNG state on
 * the next start-up.
 *
 *
 */
flea_err_e THR_flea_user__rng__save_prng_state(
  const flea_u8_t* state__pcu8,
  flea_al_u8_t     state_len__alu8
);

/**
 * This function must be called prior to using any RNG function.
 */
flea_err_e THR_flea_rng__init(
  const flea_u8_t* rng_seed__pcu8,
  flea_al_u16_t    rng_seed_len__alu16,
  flea_prng_save_f prng_save_mbn__f
);

/**
 * Function to be called at a point where no future calls to flea RNG functions are
 * conducted.
 */
void flea_rng__deinit(void);

/**
 * Fill a memory area with random bytes using the global RNG. The RNG does not perform flushing to
 * reach forward security. This function is intended to be used in repeated
 * sequence of randomize-calls for optimal performance. At the end of the
 * sequence, flea_rng__flush() shall be called to achieve forward security.
 *
 * @param mem pointer to the memory area to be randomized
 * @param mem_len the length of the area to be randomized
 *
 */
flea_err_e THR_flea_rng__randomize_no_flush(
  flea_u8_t* mem,
  flea_dtl_t mem_len
);

/**
 * Cause the global RNG to flush its state in order to achieve forward security.
 * After the flushing operation, it is not possible to recover previous output
 * from the RNG state.
 */
flea_err_e THR_flea_rng__flush(void);


#endif /* h-guard */
