/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/rng_int.h"
#include "flea/error_handling.h"

flea_err_t THR_flea_lib__init()
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_rng__init());
  FLEA_THR_FIN_SEC_empty();
}

void flea_lib__deinit()
{
  flea_rng__deinit();
}
