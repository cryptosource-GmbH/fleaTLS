/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "flea/filter.h"
#include "flea/types.h"
#include "flea/cbc_filter.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"

static flea_err_t THR_cbc_filter_process(void *custom_obj__pv, const flea_u8_t *input__pcu8, flea_dtl_t input_len__dtl, flea_u8_t *output__pu8, flea_dtl_t *output_len__pdtl)
{
  flea_cbc_filt_hlp_t *hlp__pt = (flea_cbc_filt_hlp_t *) custom_obj__pv;
  // flea_cbc_mode_ctx_t *cbc_ctx__pt = hlp__pt->cbc_ctx__pt;
  flea_al_u8_t pend_len__alu8 = hlp__pt->pend_len__u8;
  flea_dtl_t output_len__dtl  = *output_len__pdtl;
  flea_dtl_t written__dtl     = 0;

  FLEA_THR_BEG_FUNC();

  if(hlp__pt->pend_input__bu8)
  {
    flea_al_u8_t free__alu8  = hlp__pt->block_length__u8 - pend_len__alu8;
    flea_al_u8_t to_go__alu8 = FLEA_MIN(input_len__dtl, free__alu8);
    memcpy(hlp__pt->pend_input__bu8 + pend_len__alu8, input__pcu8, to_go__alu8);
    pend_len__alu8 += to_go__alu8;
    input__pcu8    += to_go__alu8;
    input_len__dtl -= to_go__alu8;
    if(pend_len__alu8 == hlp__pt->block_length__u8)
    {
      if(output_len__dtl < hlp__pt->block_length__u8)
      {
        FLEA_THROW("insufficient output space", FLEA_ERR_BUFF_TOO_SMALL);
      }
      FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(hlp__pt->cbc_ctx__pt, hlp__pt->pend_input__bu8, output__pu8, hlp__pt->block_length__u8));
      written__dtl  += hlp__pt->block_length__u8;
      pend_len__alu8 = 0;
      output__pu8   += hlp__pt->block_length__u8;
    }
  }
  // TODO: all full blocks in one call
  while(input_len__dtl >= hlp__pt->block_length__u8)
  {
    flea_al_u8_t to_go__alu8 = FLEA_MIN(input_len__dtl, hlp__pt->block_length__u8);
    if(output_len__dtl < to_go__alu8)
    {
      FLEA_THROW("insufficient output space", FLEA_ERR_BUFF_TOO_SMALL);
    }
    FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(hlp__pt->cbc_ctx__pt, input__pcu8, output__pu8, hlp__pt->block_length__u8));
    input__pcu8     += to_go__alu8;
    output__pu8     += to_go__alu8;
    input_len__dtl  -= to_go__alu8;
    output_len__dtl -= to_go__alu8;
    written__dtl    += to_go__alu8;
  }
  memcpy(hlp__pt->pend_input__bu8 + pend_len__alu8, input__pcu8, input_len__dtl);
  hlp__pt->pend_len__u8 = pend_len__alu8 + input_len__dtl;

  *output_len__pdtl = written__dtl;
  FLEA_THR_FIN_SEC_empty();
} /* THR_cbc_filter_process */

flea_err_t THR_flea_filter_t__ctor_cbc(flea_filter_t *filt__pt, flea_cbc_filt_hlp_t *uninit_cbc_hlp__pt, flea_cbc_mode_ctx_t *constructed_cbc_ctx__pt)
{
  FLEA_THR_BEG_FUNC();
  memset(uninit_cbc_hlp__pt, 0, sizeof(*uninit_cbc_hlp__pt));
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(uninit_cbc_hlp__pt->pend_input__bu8, constructed_cbc_ctx__pt->cipher_ctx__t.block_length__u8);
#endif
  uninit_cbc_hlp__pt->cbc_ctx__pt      = constructed_cbc_ctx__pt;
  uninit_cbc_hlp__pt->block_length__u8 = constructed_cbc_ctx__pt->cipher_ctx__t.block_length__u8;
  FLEA_CCALL(THR_flea_filter_t__ctor(filt__pt, (void *) uninit_cbc_hlp__pt, THR_cbc_filter_process, constructed_cbc_ctx__pt->cipher_ctx__t.block_length__u8 - 1));
  // printf("cbc filter ctor: pend_len = %u\n", uninit_cbc_hlp__pt->
  FLEA_THR_FIN_SEC_empty();
}
