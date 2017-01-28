/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/filter.h"


flea_err_t THR_flea_filter_t__ctor(flea_filter_t *filt__pt, void * custom_obj__pv, flea_filter_process_f proc__f, flea_al_u16_t max_absolute_output_expansion__alu16)
{
  FLEA_THR_BEG_FUNC();
  filt__pt->ctx__pv = custom_obj__pv;
  filt__pt->proc__f = proc__f;
  filt__pt->max_absolute_output_expansion__u16 = max_absolute_output_expansion__alu16;
    FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_filter_t__process(flea_filter_t * filt__pt, const flea_u8_t *input__pcu8, flea_dtl_t input_len__dtl, flea_u8_t *output__pu8, flea_dtl_t *output_len__pdtl)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(filt__pt->proc__f(filt__pt->ctx__pv, input__pcu8, input_len__dtl, output__pu8, output_len__pdtl));

  FLEA_THR_FIN_SEC_empty();
} 

#if 0
flea_err_t THR_flea_filter_t__process_to_stream(flea_filter_t * filt__pt, const flea_u8_t *input__pcu8, flea_dtl_t input_len__dtl, flea_rw_stream_t * write_stream__pt)
{

    flea_cbc_filt_hlp_t * hlp__pt = (flea_cbc_filt_hlp_t*) custom_obj__pv;
    //flea_cbc_mode_ctx_t *cbc_ctx__pt = hlp__pt->cbc_ctx__pt;
    flea_al_u8_t pend_len__alu8 = hlp__pt->pend_len__u8;
    flea_dtl_t output_len__dtl = *output_len__pdtl;
    FLEA_THR_BEG_FUNC();
   if(hlp__pt->pend_input__bu8)
   {
     flea_al_u8_t free__alu8 = hlp__pt->block_length__u8 - pend_len__alu8;
     flea_al_u8_t to_go__alu8 = FLEA_MIN(input_len__dtl, free__alu8);
     memcpy(hlp__pt->pend_input__bu8 + pend_len__alu8, input__pcu8, to_go__alu8);
     pend_len__alu8 += to_go__alu8;
     input__pcu8 += to_go__alu8;
     input_len__dtl -= to_go__alu8;
     if(pend_len__alu8 == hlp__pt->block_length__u8)
     {
       if(output_len__dtl < hlp__pt->block_length__u8)
       {
         FLEA_THROW("insufficient output space", FLEA_ERR_BUFF_TOO_SMALL); 
       }
       FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(hlp__pt->cbc_ctx__pt, hlp__pt->pend_input__bu8, output__pu8, hlp__pt->block_length__u8));
       pend_len__alu8 = 0;
       output__pu8 += hlp__pt->block_length__u8;

     }
     while(input_len__dtl >= hlp__pt->block_length__u8)
     {
       flea_al_u8_t to_go__alu8 = FLEA_MIN(input_len__dtl, hlp__pt->block_length__u8);
       if(output_len__dtl < to_go__alu8)
       {
         FLEA_THROW("insufficient output space", FLEA_ERR_BUFF_TOO_SMALL); 
       }
       FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(hlp__pt->cbc_ctx__pt, input__pcu8, output__pu8, hlp__pt->block_length__u8));
       input__pcu8 += to_go__alu8; 
       output__pu8 += to_go__alu8; 
       input_len__dtl -= to_go__alu8;
       output_len__dtl -= to_go__alu8;
     }
     memcpy(hlp__pt->pend_input__bu8, input__pcu8, input_len__dtl);
     hlp__pt->pend_len__u8 = input_len__dtl; 
   }
    FLEA_THR_FIN_SEC_empty();
}
#endif 
