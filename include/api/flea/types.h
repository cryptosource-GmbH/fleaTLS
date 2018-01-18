/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef __types_H_
#define __types_H_

#include "internal/common/default.h"
#include "flea/error.h"
#include "internal/common/types_int.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Integer representing a boolean value.
 */
typedef flea_al_u8_t flea_bool_t;

#define FLEA_FALSE 0
#define FLEA_TRUE  1

/**
 * Integer representing data lengths. Is used throughout the fleaTLS API.
 */
#ifdef FLEA_HAVE_DTL_32BIT

typedef flea_u32_t flea_dtl_t;
#else

typedef flea_u16_t flea_dtl_t;
#endif

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
