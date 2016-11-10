/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/types.h"

#ifndef _flea_lib__H_
#define _flea_lib__H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function must be called prior to any other function of the flea library
 * at the devices startup. If the return value of this function indicates an
 * error, then no cryptographic functions may be used.
 */
flea_err_t THR_flea_lib__init(void);

/**
 * Function that may be called at a point after which no more
 * functions of flea are used.
 */
void flea_lib__deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
