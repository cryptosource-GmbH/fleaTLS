/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cbc_filter__H_
#define _flea_cbc_filter__H_

#include "flea/types.h"
#include "flea/error.h"
#include "flea/block_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t           *pend_input__bu8;
#else
  flea_u8_t           pend_input__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif
  flea_cbc_mode_ctx_t *cbc_ctx__pt;
  flea_u8_t           block_length__u8;
  flea_u8_t           pend_len__u8;
} flea_cbc_filt_hlp_t;

flea_err_t
THR_flea_filter_t__ctor_cbc(flea_filter_t *filt__pt, flea_cbc_filt_hlp_t *uninit_cbc_hlp__pt, flea_cbc_mode_ctx_t *constructed_cbc_ctx__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
