/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/types.h"

#ifndef _flea_lib__H_
# define _flea_lib__H_

# ifdef __cplusplus
extern "C" {
# endif


/**
 * function type for a function to be called by the flea's RNG that saves a PRNG state. The saved PRNG state is supposed to be used during the next flea cycle as the seed value supplied to the function THR_flea_lib__init().
 *
 * @param state__pcu8 pointer to the memory area with the PRNG state to be
 * saved.
 *
 * @param state_len__alu8 length of state__pcu8
 *
 * @return an error value if there was an error saving the PRNG state.
 */
typedef flea_err_t (* flea_prng_save_f)(
  const flea_u8_t* state__pcu8,
  flea_al_u8_t     state_len__alu8
);

/**
 * This function must be called prior to any other function of the flea library
 * at the devices startup. If the return value of this function indicates an
 * error, then no cryptographic functions may be used. Note that a high entropy
 * seed must be provided to this function, otherwise the operation of flea's
 * global RNG will be insecure. It is the caller's responsibility to provide a
 * seed of appropriate length and entropy.
 *
 * @param rng_seed__pcu8 a fresh high-entropy prng seed for the initialization of flea's library RNG. It is recommended to used the value saved by the flea_prng_save_f function provided to THR_flea_lib__init().
 * @param rng_seed_len__alu16 length of rng_seed__pcu8. This function will
 * always be called with the value FLEA_AES256_KEY_BYTE_LENGTH from flea.
 * @param save__f pointer to a function that saves a freshly generated PRNG state for future
 * use in a call to THR_flea_lib__init(). This function pointer may be null. In this case it is the necessary to
 * ensure by other means that the PRNG receives a fresh seed whenever THR_flea_lib__init() is called.
 */
flea_err_t THR_flea_lib__init(
  const flea_u8_t* rng_seed__pcu8,
  flea_al_u16_t    rng_seed_len__alu16,
  flea_prng_save_f save_mbn__f
);

/**
 * Function that may be called at a point after which no more
 * functions of flea are used.
 */
void flea_lib__deinit(void);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
