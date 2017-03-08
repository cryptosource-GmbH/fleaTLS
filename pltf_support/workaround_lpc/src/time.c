/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/pltf_if/time.h"
#include "flea/error_handling.h"
#include <time.h>

flea_err_t THR_flea_pltfif_time__get_current_time(flea_gmt_time_t* time__t)
{
  FLEA_THR_BEG_FUNC();
  time__t->year    = 2018;
  time__t->month   = 3;
  time__t->day     = 16;
  time__t->hours   = 0;
  time__t->seconds = 0;
  time__t->minutes = 0;
  FLEA_THR_FIN_SEC_empty();
}
