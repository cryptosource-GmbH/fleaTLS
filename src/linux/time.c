/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/pltf_if/time.h"
#include "flea/error_handling.h"
#include <time.h>

flea_err_t flea_pltfif_time__get_current_time(flea_gmt_time_t *time__t)
{

  time_t t;
  struct tm *ts;

  FLEA_THR_BEG_FUNC();
  t = time(NULL);
  ts = gmtime(&t);
  time__t->year = ts->tm_year + 1900;
  time__t->month = ts->tm_mon + 1;
  time__t->day = ts->tm_mday;
  time__t->hours = ts->tm_hour;
  time__t->seconds = ts->tm_sec % 60;
  time__t->minutes = ts->tm_min;

  FLEA_THR_FIN_SEC_empty(); 
}
