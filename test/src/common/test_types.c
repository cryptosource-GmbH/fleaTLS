/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/types.h"
#include "flea/error.h"
#include "self_test.h"

flea_err_t THR_flea_test_flea_types()
{
  FLEA_THR_BEG_FUNC();
  if(sizeof(flea_u8_t) != 1)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_s8_t) != 1)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_u16_t) != 2)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_s16_t) != 2)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_u32_t) != 4)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_s32_t) != 4)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_sword_t) != sizeof(flea_uword_t))
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_dbl_uword_t) != 2 * sizeof(flea_uword_t))
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_dbl_sword_t) != 2 * sizeof(flea_sword_t))
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_flea_types */
