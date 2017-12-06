/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/rng_int.h"
#include "flea/error_handling.h"
#include "flea/lib.h"

flea_err_t THR_flea_lib__init(
  const flea_u8_t* rng_seed__pcu8,
  flea_al_u16_t    rng_seed_len__alu16,
  flea_prng_save_f prng_save__f
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_rng__init(rng_seed__pcu8, rng_seed_len__alu16, prng_save__f));
  FLEA_THR_FIN_SEC_empty();
}

void flea_lib__deinit()
{
  flea_rng__deinit();
}
