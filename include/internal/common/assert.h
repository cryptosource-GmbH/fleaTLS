/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_assert__H_
#define _flea_assert__H_

#include "internal/common/default.h"
#include "flea/error_handling.h"

#ifdef FLEA_NO_DEV_ASSERTIONS
# define FLEA_DEV_ASSERT(x)
#else
# define FLEA_DEV_ASSERT(x) \
  do { \
    if(!(x)) { \
      __FLEA_EVTL_PRINT_ERR(__func__, "assertion failed"); \
      exit(1); \
    } while(0)
#endif // ifdef FLEA_NO_DEV_ASSERTIONS

#endif /* h-guard */
