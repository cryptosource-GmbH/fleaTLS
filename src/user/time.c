/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/pltf_if/time.h"
#include "flea/error_handling.h"

#ifdef FLEA_USE_USER_CURR_TIME
flea_err_t flea_pltfif_time__get_current_time(flea_gmt_time_t *time__t)
{
  FLEA_THR_BEG_FUNC();
#error flea_pltfif_time__get_current_time needs to be implemented
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_USE_USER_CURR_TIME */
