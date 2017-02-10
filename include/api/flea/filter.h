/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_filter__H_
#define _flea_filter__H_

#include "flea/types.h"
#include "flea/error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef flea_err_t (* flea_filter_process_f)(
  void*            custom_obj__pv,
  const flea_u8_t* input__pcu8,
  flea_dtl_t       input_len__dtl,
  flea_u8_t*       output__pu8,
  flea_dtl_t*      output_len__pdtl
);

typedef struct
{
  flea_filter_process_f proc__f;
  void*                 ctx__pv;
  flea_u16_t            max_absolute_output_expansion__u16;
} flea_filter_t;

flea_err_t THR_flea_filter_t__ctor(
  flea_filter_t*        filt__pt,
  void*                 custom_obj__pv,
  flea_filter_process_f proc__f,
  flea_al_u16_t         max_absolute_output_expansion__dtl
);

flea_err_t THR_flea_filter_t__process(
  flea_filter_t*   filt__pt,
  const flea_u8_t* input__pcu8,
  flea_dtl_t       input_len__dtl,
  flea_u8_t*       output__pu8,
  flea_dtl_t*      output_len__pdtl
);

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
