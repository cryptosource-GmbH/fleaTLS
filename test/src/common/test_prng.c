/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/hash.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/ctr_mode_prng.h"
#include "flea/rng.h"
#include "flea/algo_config.h"
#include <string.h>


static flea_err_e THR_flea_test_ctr_mode_prng_init_dtor()
{
  flea_ctr_mode_prng_t prng_ctx__t;
  flea_ctr_mode_prng_t prng_ctx2__t;

  FLEA_THR_BEG_FUNC();
  flea_ctr_mode_prng_t__INIT(&prng_ctx2__t);
  flea_ctr_mode_prng_t__INIT(&prng_ctx__t);

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_prng_t__dtor(&prng_ctx__t);
    flea_ctr_mode_prng_t__dtor(&prng_ctx2__t);
  );
}

flea_err_e THR_flea_test_ctr_mode_prng()
{
  FLEA_DECL_BUF(rnd__bu8, flea_u8_t, 17);
  flea_ctr_mode_prng_t prng_ctx__t;
  flea_ctr_mode_prng_t__INIT(&prng_ctx__t);
  flea_u8_t seed__au8[] = {0xd6, 0x93, 0x35, 0xb9, 0x33, 0x25, 0x19, 0x2e, 0x51, 0x6a, 0x91, 0x2e, 0x6d, 0x19, 0xa1, 0x5c, 0xb5, 0x1c, 0x6e, 0xd5, 0xc1, 0x52, 0x43, 0xe7, 0xa7, 0xfd, 0x65, 0x3c};
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(rnd__bu8, 17);

  FLEA_CCALL(THR_flea_ctr_mode_prng_t__ctor(&prng_ctx__t, NULL, 0));
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&prng_ctx__t, seed__au8, sizeof(seed__au8)));

  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&prng_ctx__t, seed__au8, 1));
  flea_ctr_mode_prng_t__randomize_no_flush(&prng_ctx__t, rnd__bu8, 17);
  flea_ctr_mode_prng_t__randomize(&prng_ctx__t, rnd__bu8, 17);
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&prng_ctx__t, rnd__bu8, 17));

  FLEA_CCALL(THR_flea_test_ctr_mode_prng_init_dtor());

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_prng_t__dtor(&prng_ctx__t);
    FLEA_FREE_BUF_FINAL(rnd__bu8);
  );
}

flea_err_e THR_flea_test_feed_entropy()
{
  FLEA_THR_BEG_FUNC();
  flea_u16_t pseudo = 42;
  flea_al_u8_t est  = 16;
  flea_al_u8_t i;
  for(i = 0; i < 16; i++)
  {
    flea_rng__feed_low_entropy_data_to_pool(pseudo, est);
  }
  FLEA_CCALL(THR_flea_rng__randomize((flea_u8_t*) &pseudo, sizeof(pseudo)));
  FLEA_THR_FIN_SEC_empty();
}
