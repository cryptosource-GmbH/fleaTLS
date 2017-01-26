/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/alloc.h"
#include "flea/types.h"

#ifdef FLEA_USE_BUF_DBG_CANARIES
static flea_u8_t flea_dbg_canaries_flag = 0;

void flea_dbg_canaries__signal_canary_error()
{
  flea_dbg_canaries_flag = 1;
}
void flea_dbg_canaries__clear_canary_error()
{
  flea_dbg_canaries_flag = 0;
}
int flea_dbg_canaries__is_canary_error_set()
{
  return flea_dbg_canaries_flag != 0;
}

#endif
