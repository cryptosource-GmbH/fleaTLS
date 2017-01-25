/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_gcm__H_
#define _flea_gcm__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/block_cipher.h"
#include "internal/common/len_ctr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct 
{
    flea_len_ctr_t len_ctr__t;
    flea_u16_t add_len;       
//#ifdef FLEA_USE_HEAP_BUF
    flea_u32_t HL[32];       
    flea_u32_t HH[32];      
    flea_u8_t base_ectr[16];
    flea_u8_t y[16];       
    flea_u8_t buf[16];    
//#endif
    flea_u8_t pend_input__bu8[16];
    flea_u8_t pend_input_len__u8;
} flea_ghash_ctx_t;

flea_err_t THR_flea_ghash_ctx_t__init( flea_ghash_ctx_t *ctx__pt,   
    const flea_ecb_mode_ctx_t *ecb_ctx__pt);

flea_err_t THR_flea_ghash_ctx_t__start( flea_ghash_ctx_t *ctx, const flea_ecb_mode_ctx_t * ecb_ctx__pt, const flea_u8_t *iv, size_t iv_len, const flea_u8_t *add, size_t add_len);

flea_err_t THR_flea_ghash_ctx_t__update( flea_ghash_ctx_t *ctx, flea_dtl_t length, const flea_u8_t *input);

void flea_ghash_ctx_t__finish(flea_ghash_ctx_t *ctx, flea_u8_t *tag, size_t tag_len); 

void flea_ghash_ctx_t__dtor(flea_ghash_ctx_t *ctx__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
