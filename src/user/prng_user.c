/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/block_cipher/aes.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
static flea_u8_t gl_prng_state__au8[FLEA_AES256_KEY_BYTE_LENGTH] = { 0 };

flea_err_t THR_flea_user__rng__load_prng_state (flea_u8_t* result__bu8, flea_al_u8_t result_len__alu8)
{
  FLEA_THR_BEG_FUNC();
  if(result_len__alu8 != sizeof(gl_prng_state__au8))
  {
    FLEA_THROW("wrong length of PRNG state", FLEA_ERR_INT_ERR);
  }
  // must be implemented by user: load the last saved PRNG state from the NVM.
  // The reserved area must have size sizeof(gl_prng_state__au8).
  // ##__FLEA_UNCOMMENT_IN_RELEASE__## #error for the security of your implementation, you have to implement this function for loading of the PRNG state
  // comment in the following line FOR TESTING PURPOSES ONLY, this leads to completely INSECURE
  // behaviour of random number generation:
  /* ##__FLEA_COMMENT_OUT_IN_RELEASE__## */ memcpy(result__bu8, gl_prng_state__au8, sizeof(gl_prng_state__au8));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_user__rng__save_prng_state (const flea_u8_t* state__pcu8, flea_al_u8_t state_len__alu8)
{
  FLEA_THR_BEG_FUNC();
  if(state_len__alu8 != sizeof(gl_prng_state__au8))
  {
    FLEA_THROW("wrong length of PRNG state", FLEA_ERR_INT_ERR);
  }
  // must be implemented by user: store the current PRNG state in NVM.
  // ##__FLEA_UNCOMMENT_IN_RELEASE__## #error for the security of your implementation, you have to implement this function for saving of the PRNG state
  // comment in the following line FOR TESTING PURPOSES ONLY, this leads to completely INSECURE
  // behaviour of random number generation:
  /* ##__FLEA_COMMENT_OUT_IN_RELEASE__## */ memcpy(gl_prng_state__au8, state__pcu8, state_len__alu8);  // comment in for testing purposes only
  FLEA_THR_FIN_SEC_empty();
}
