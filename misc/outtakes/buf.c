/***********************************
 *
 *
 * ___________________
 * ***** cryptosource 
 * *******************
 *
 * flea cryptographic library 
 *
 * (C) cryptosource GmbH 2014
 *
 * This software is made available to you only under the separately received license
 * conditions.
 *
 */

#include "internal/common/default.h"
#include "flea/buf.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "internal/common/alloc_dbg_int.h"

#ifdef FLEA_USE_BUF_DBG_CANARIES
flea_u8_t flea_dbg_canaries_flag = 0;
#endif

void flea_free_u32_buf_secret(flea_u32_buf_t* buf)
{
#ifdef FLEA_USE_HEAP_BUF
          if(buf->buf) 
#endif
          { 
            flea_memzero_secure((flea_u8_t*)buf->buf, buf->len*sizeof(buf->buf[0])); 
            FLEA_SIGNAL_ERROR_IF_BUF_DBG_CANARIES_NOT_OK_SWITCHED(*buf);
#ifdef FLEA_USE_HEAP_BUF
            FLEA_FREE_MEM(((flea_u8_t*)buf->buf)-FLEA_ALLOC_BUF_OFFS_FOR_DBG_CANARIES_SWITCHED);
            buf->buf = NULL;
#endif
          } 
}

void flea_free_u16_buf_secret(flea_u16_buf_t* buf)
{
#ifdef FLEA_USE_HEAP_BUF
          if(buf->buf) 
#endif
          { 
            flea_memzero_secure((flea_u8_t*)buf->buf, buf->len*sizeof(buf->buf[0])); 
            FLEA_SIGNAL_ERROR_IF_BUF_DBG_CANARIES_NOT_OK_SWITCHED(*buf);
#ifdef FLEA_USE_HEAP_BUF
            FLEA_FREE_MEM(((flea_u8_t*)buf->buf)-FLEA_ALLOC_BUF_OFFS_FOR_DBG_CANARIES_SWITCHED);
            buf->buf = NULL;
#endif
          } 
}

void flea_free_u8_buf_secret(flea_u8_buf_t* buf)
{
#ifdef FLEA_USE_HEAP_BUF
          if(buf->buf) 
#endif
          { 
            flea_memzero_secure((flea_u8_t*)buf->buf, buf->len*sizeof(buf->buf[0])); 
            FLEA_SIGNAL_ERROR_IF_BUF_DBG_CANARIES_NOT_OK_SWITCHED(*buf);
#ifdef FLEA_USE_HEAP_BUF
            FLEA_FREE_MEM(buf->buf-FLEA_ALLOC_BUF_OFFS_FOR_DBG_CANARIES_SWITCHED);
            buf->buf = NULL;
#endif
          } 
}
