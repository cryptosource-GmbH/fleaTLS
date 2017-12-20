/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/rng_int.h"
#include "flea/error_handling.h"
#include "internal/common/lib_int.h"
#include "internal/common/mutex_int.h"

static flea_gmt_time_now_f flea_gl_get_current_time__f = NULL;

flea_err_e THR_flea_lib__get_gmt_time_now(flea_gmt_time_t* time__pt)
{
  if(flea_gl_get_current_time__f != NULL)
  {
    return flea_gl_get_current_time__f(time__pt);
  }
  return FLEA_ERR_NOW_FUNC_IS_NULL;
}

flea_err_e THR_flea_lib__init(
  flea_gmt_time_now_f          now__f,
  const flea_u8_t*             rng_seed__pcu8,
  flea_al_u16_t                rng_seed_len__alu16,
  flea_prng_save_f prng_save__f
#ifdef                         FLEA_HAVE_MUTEX
  ,
  const flea_mutex_func_set_t* mutex_func_set__pt
#endif

)
{
  FLEA_THR_BEG_FUNC();
  flea_gl_get_current_time__f = now__f;
#ifdef FLEA_HAVE_MUTEX
  flea_mutex__set_funcs(mutex_func_set__pt);
#endif
  FLEA_CCALL(THR_flea_rng__init(rng_seed__pcu8, rng_seed_len__alu16, prng_save__f));
  FLEA_THR_FIN_SEC_empty();
}

void flea_lib__deinit()
{
  flea_rng__deinit();
}
