/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_byte_vec_int__H_
#define _flea_byte_vec_int__H_

#include "flea/byte_vec.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Sets the contents of the byte vector from src using the the external
 * memory. Thus the vector becomes a reference.
 */
void flea_byte_vec_t__copy_content_set_ref_use_mem(
  flea_byte_vec_t*       trgt,
  flea_u8_t*             trgt_mem,
  const flea_byte_vec_t* src
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
