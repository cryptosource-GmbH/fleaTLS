/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/pltf_if/time.h"
#include "flea/error_handling.h"

flea_err_t THR_flea_test_gmt_time()
{
  flea_gmt_time_t time__t;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_pltfif_time__get_current_time(&time__t));

  //printf("time = %i-%i-%i %i:%i:%i \n", time__t.year, time__t.month, time__t.day, time__t.hours, time__t.minutes, time__t.seconds);
  FLEA_THR_FIN_SEC_empty();

}
