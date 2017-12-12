/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/lib_int.h"
#include "flea/error_handling.h"
#include "flea/lib.h"
#include "self_test.h"

flea_err_t THR_flea_test_gmt_time()
{
  flea_gmt_time_t time__t;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_lib__get_gmt_time_now(&time__t));

  FLEA_THR_FIN_SEC_empty();
}
