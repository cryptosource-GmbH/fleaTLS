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

#ifndef _flea_buf__H_
#define _flea_buf__H_

#include "flea/types.h"

typedef struct
{
  flea_u32_t* buf;
  flea_dtl_t len;
    
} flea_u32_buf_t;

typedef struct
{
  flea_u16_t* buf;
  flea_dtl_t len;
} flea_u16_buf_t;

typedef struct
{
  flea_u8_t* buf;
  flea_dtl_t len;
} flea_u8_buf_t;


#   define FLEA_FBUF_SET_CANANRIES(__name, __size) \
  do { \
    ((flea_u8_t*)(__name))[-4] = 0xDE; \
    ((flea_u8_t*)(__name))[-3] = 0xAD; \
    ((flea_u8_t*)(__name))[-2] = 0xBE; \
    ((flea_u8_t*)(__name))[-1] = 0xEF;\
    ((flea_u8_t*)(&__name[__size]))[ 0] = 0xA5;\
    ((flea_u8_t*)(&__name[__size]))[ 1] = 0xAF;\
    ((flea_u8_t*)(&__name[__size]))[ 2] = 0x49;\
    ((flea_u8_t*)(&__name[__size]))[ 3] = 0x73;\
  } while(0)

#   define FLEA_FBUF_DBG_CANARIES_ARE_NOT_OK(__name, __size) \
              (((flea_u8_t*)(__name))[-4] != 0xDE || \
              ((flea_u8_t*)(__name))[-3] != 0xAD || \
              ((flea_u8_t*)(__name))[-2] != 0xBE || \
              ((flea_u8_t*)(__name))[-1] != 0xEF || \
              ((flea_u8_t*)(&__name[__size]))[ 0] != 0xA5 || \
              ((flea_u8_t*)(&__name[__size]))[ 1] != 0xAF || \
              ((flea_u8_t*)(&__name[__size]))[ 2] != 0x49 || \
              ((flea_u8_t*)(&__name[__size]))[ 3] != 0x73)

# ifdef FLEA_USE_BUF_DBG_CANARIES
#define FLEA_SIGNAL_ERROR_IF_BUF_DBG_CANARIES_NOT_OK_SWITCHED(__buf) do { if(FLEA_FBUF_DBG_CANARIES_ARE_NOT_OK((__buf).buf, (__buf).len)) { __FLEA_SIGNAL_DBG_CANARY_ERROR();} } while (0)
#define FLEA_ALLOC_BUF_OFFS_FOR_DBG_CANARIES_SWITCHED 4
#else
#define FLEA_SIGNAL_ERROR_IF_BUF_DBG_CANARIES_NOT_OK_SWITCHED(__buf)
#define FLEA_ALLOC_BUF_OFFS_FOR_DBG_CANARIES_SWITCHED 0
#endif



#ifdef FLEA_USE_STACK_BUF
#ifndef FLEA_USE_BUF_DBG_CANARIES
#define FLEA_DECL_U32_BUF(__name, __len) \
    flea_uword_t __##__name##__RAW_ARR [__len]; \
    flea_uword_buf_t __name = {.buf = __##__name##__RAW_ARR, .len = __len }
#define FLEA_DECL_U16_BUF(__name, __len) \
    flea_hlf_uword_t __##__name##__RAW_ARR [__len]; \
    flea_hlf_uword_buf_t __name = {.buf = __##__name##__RAW_ARR, .len = __len }
#define FLEA_DECL_U8_BUF(__name, __len) \
    flea_u8_t __##__name##__RAW_ARR [__len]; \
    flea_u8_buf_t __name = {.buf = __##__name##__RAW_ARR, .len = __len }
#define FLEA_FREE_FBUF_FINAL(__buf)
#define FLEA_FREE_FBUF(__buf)
#else // #ifndef FLEA_USE_BUF_DBG_CANARIES
#define FLEA_DECL_U32_BUF(__name, __len) \
    flea_uword_t __##__name##__RAW_ARR [__len+8]; \
    flea_uword_buf_t __name = {.buf = ((flea_uword_t*)(((flea_u8_t*)__##__name##__RAW_ARR)+4)), .len = __len }; \
    FLEA_FBUF_SET_CANANRIES(__name.buf, __name.len)

#define FLEA_DECL_U16_BUF(__name, __len) \
    flea_hlf_uword_t __##__name##__RAW_ARR [__len+8]; \
    flea_hlf_uword_buf_t __name = {.buf = ((flea_hlf_uword_t*)(((flea_u8_t*)__##__name##__RAW_ARR)+4)), .len = __len }; \
    FLEA_FBUF_SET_CANANRIES(__name.buf, __name.len)

#define FLEA_DECL_U8_BUF(__name, __len) \
    flea_u8_t __##__name##__RAW_ARR [__len+8]; \
    flea_u8_buf_t __name = {.buf = ((flea_u8_t*)(((flea_u8_t*)__##__name##__RAW_ARR)+4)), .len = __len }; \
    FLEA_FBUF_SET_CANANRIES(__name.buf, __name.len)

#define FLEA_FREE_FBUF_FINAL(__buf) \
      if(__buf.buf != NULL && FLEA_FBUF_DBG_CANARIES_ARE_NOT_OK(__buf.buf, __buf.len)) {__FLEA_SIGNAL_DBG_CANARY_ERROR(); }  
#define FLEA_FREE_FBUF(__buf) FLEA_FREE_FBUF_FINAL(__buf)
      
  

#endif // #else of #ifndef FLEA_USE_BUF_DBG_CANARIES

# ifndef FLEA_USE_BUF_DBG_CANARIES
#   define FLEA_ALLOC_FBUF(__buf, __len) 
#else
#   define FLEA_ALLOC_FBUF(__buf, __len) 
# endif
#else // #ifdef FLEA_USE_STACK_BUF




# ifndef FLEA_USE_BUF_DBG_CANARIES


#define FLEA_DECL_U16_BUF(__name, __len) \
    flea_hlf_uword_buf_t __name = {.buf = NULL, .len = 0 }
#define FLEA_DECL_U32_BUF(__name, __len) \
    flea_uword_buf_t __name = {.buf = NULL, .len = 0 }
#define FLEA_DECL_U8_BUF(__name, __len) \
    flea_u8_buf_t __name = {.buf = NULL, .len = 0 }
#define FLEA_FREE_FBUF_FINAL(__buf) FLEA_FREE_MEM_CHK_NULL((__buf).buf)
#define FLEA_FREE_FBUF(__buf) FLEA_FREE_MEM_CHK_SET_NULL((__buf).buf)
#   define FLEA_ALLOC_FBUF(__buf, __len) \
  do { \
      FLEA_ALLOC_MEM((__buf).buf, sizeof(__buf.buf[0])*(__len)); \
      __buf.len = __len; \
  } while(0)
# else // #ifndef FLEA_USE_BUF_DBG_CANARIES

#define FLEA_DECL_U16_BUF(__name, __len) \
    flea_hlf_uword_buf_t __name = {.buf = NULL, .len = 0 }; \
    typedef flea_hlf_uword_t __name##_DBG_CANARIES_HELP_TYPE; 
    
#define FLEA_DECL_U32_BUF(__name, __len) \
    flea_uword_buf_t __name = {.buf = NULL, .len = 0 }; \
    typedef flea_uword_t __name##_DBG_CANARIES_HELP_TYPE; 

#define FLEA_DECL_U8_BUF(__name, __len) \
    flea_u8_buf_t __name = {.buf = NULL, .len = 0 }; \
    typedef flea_u8_t __name##_DBG_CANARIES_HELP_TYPE; 

#   define FLEA_ALLOC_FBUF(__buf, __len) \
  do { \
    flea_u8_t* tmp; \
      FLEA_ALLOC_MEM(tmp, sizeof(__buf.buf[0])*(__len)+8); \
      (__buf).buf = (__buf##_DBG_CANARIES_HELP_TYPE*) (tmp + 4); \
      __buf.len = __len; \
      FLEA_FBUF_SET_CANANRIES(__buf.buf, __buf.len); \
  } while(0)

#define FLEA_FREE_FBUF_FINAL(__buf) \
        do { \
          if(__buf.buf) { \
            if( FLEA_FBUF_DBG_CANARIES_ARE_NOT_OK(__buf.buf, __buf.len)) \
            { __FLEA_SIGNAL_DBG_CANARY_ERROR(); }  /* we might be in the cleanup section and cannot use THROW*/ \
            FLEA_FREE_MEM(((flea_u8_t*)__buf.buf)-4); \
          } \
        } while(0)
#define FLEA_FREE_FBUF(__buf) \
        do { \
          if(__buf.buf) { \
            if( FLEA_FBUF_DBG_CANARIES_ARE_NOT_OK(__buf.buf, __buf.len)) \
            { __FLEA_SIGNAL_DBG_CANARY_ERROR(); }  /* we might be in the cleanup section and cannot use THROW*/ \
            FLEA_FREE_MEM(((flea_u8_t*)__buf.buf)-4); \
            __buf.buf = NULL; \
          } \
        } while(0)

# endif // #else of #ifndef FLEA_USE_BUF_DBG_CANARIES

#endif // #else of #ifdef FLEA_USE_STACK_BUF



#ifdef FLEA_HAVE_32BIT_WORD
#define FLEA_DECL_UW_BUF(a,b) FLEA_DECL_U32_BUF(a, b)
#define FLEA_DECL_HW_BUF(a,b) FLEA_DECL_U16_BUF(a, b)
#define FLEA_FREE_UWORD_BUF_SECRET(a) flea_free_u32_buf_secret(a)
#define FLEA_FREE_HLF_UW_BUF_SECRET(a) flea_free_u16_buf_secret(a)
typedef flea_u32_buf_t flea_uword_buf_t;
typedef flea_u16_buf_t flea_hlf_uword_buf_t;
#elif defined FLEA_HAVE_16BIT_WORD
#define FLEA_DECL_UW_BUF(a,b) FLEA_DECL_U16_BUF(a, b)
#define FLEA_DECL_HW_BUF(a,b) FLEA_DECL_U8_BUF(a, b)
#define FLEA_FREE_UWORD_BUF_SECRET(a) flea_free_u16_buf_secret(a)
#define FLEA_FREE_HLF_UW_BUF_SECRET(a) flea_free_u8_buf_secret(a)
typedef flea_u16_buf_t flea_uword_buf_t;
typedef flea_u8_buf_t flea_hlf_uword_buf_t;
#else
#error flea word size not defined
#endif 

void flea_free_u32_buf_secret(flea_u32_buf_t* buf);
void flea_free_u16_buf_secret(flea_u16_buf_t* buf);
void flea_free_u8_buf_secret(flea_u8_buf_t* buf);


#endif /* h-guard */
