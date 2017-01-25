/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/ae.h"
#include "flea/bin_utils.h"
#include "internal/common/hash/ghash.h"
#include "flea/error_handling.h"

static const flea_u16_t ghash_lo[16] = 
{
  0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0 
};
// TODO:
#define PUT_UINT32_BE(n,b,i) {                      \
    (b)[(i)    ] = (flea_u8_t) ( (n) >> 24 );   \
    (b)[(i) + 1] = (flea_u8_t) ( (n) >> 16 );   \
    (b)[(i) + 2] = (flea_u8_t) ( (n) >>  8 );   \
    (b)[(i) + 3] = (flea_u8_t) ( (n)       ); }



/**
 * Lshift smaller than shiftwidth 32 
 */
#define FLEA_LSHIFT_U64_AU32_SMALL(in, out, shift) \
do{ \
  out[1]= (in[1] << shift); \
  if(shift <= 32) { out[1] |= (in[0] >> (32 - shift));} \
  out[0] = in[0] << shift; \
}while(0);


#define FLEA_RSHIFT_U64_AU32_SMALL(in, out, shift) \
do{ \
  out[0]= (in[0] >> shift); \
  if(shift <= 32) { out[0] |= (in[1] << (32 - shift));} \
  out[1] = in[1] >> shift; \
}while(0);

/**
 * Lshift greater or equal than 32
 */
#define FLEA_LSHIFT_U64_AU32_LARGE(in, out, shift) \
do{ \
  out[1]= (in[0] << (32 - ( 64 - shift))); \
  out[0] = 0; \
}while(0);

#define FLEA_U64_OR_AU32(au32_in_out, au32_in) \
  do { \
    au32_in_out[0] |= au32_in[0]; \
    au32_in_out[1] |= au32_in[1]; \
  }while(0)

static void ghash_process_block( flea_ghash_ctx_t *ctx__pt, const flea_u8_t x[16], flea_u8_t output[16]) 
{
    int i;
    flea_u8_t lo, hi, rem;
    flea_u32_t zl_a[2];
    flea_u32_t zh_a[2];
    flea_u32_t tmp_a[2];
    lo = (flea_u8_t)( x[15] & 0x0f );
    hi = (flea_u8_t)( x[15] >> 4 );
    zh_a[0] = ctx__pt->HH[2*lo];
    zh_a[1] = ctx__pt->HH[2*lo+1];

    zl_a[0] = ctx__pt->HL[2*lo];
    zl_a[1] = ctx__pt->HL[2*lo+1];
    
    for( i = 29; i >= -1; i-- ) 
    {
      if(i & 1)
      {
        hi = (flea_u8_t) ( x[(i+1)/2] >> 4 );
      }
      else
      {
        hi = (flea_u8_t) ( x[(i+1)/2] & 0x0f );
      }
        rem = (flea_u8_t) ( zl_a[0] & 0x0f );

        FLEA_LSHIFT_U64_AU32_LARGE(zh_a, tmp_a, 60);
        FLEA_RSHIFT_U64_AU32_SMALL(zl_a, zl_a, 4);
        FLEA_U64_OR_AU32(zl_a, tmp_a);
        FLEA_RSHIFT_U64_AU32_SMALL(zh_a, zh_a, 4);

        tmp_a[0] = ghash_lo[rem];
        tmp_a[1] = 0;
        FLEA_LSHIFT_U64_AU32_LARGE(tmp_a, tmp_a, 48);
        zh_a[0] ^= tmp_a[0];
        zh_a[1] ^= tmp_a[1];


        zh_a[0] ^= ctx__pt->HH[2*hi];
        zh_a[1] ^= ctx__pt->HH[2*hi+1];

        zl_a[0] ^= ctx__pt->HL[2*hi];
        zl_a[1] ^= ctx__pt->HL[2*hi+1];
    }
    PUT_UINT32_BE( zh_a[1], output, 0 );
    PUT_UINT32_BE( zh_a[0], output, 4 );
    PUT_UINT32_BE( zl_a[1], output, 8 );
    PUT_UINT32_BE( zl_a[0], output, 12 );
}

flea_err_t THR_flea_ghash_ctx_t__init( flea_ghash_ctx_t *ctx__pt,   
    const flea_ecb_mode_ctx_t *ecb_ctx__pt
                ) 
{
    int i, j;
    flea_u32_t vl_a[2], vh_a[2];
    flea_u8_t h[16];

    FLEA_THR_BEG_FUNC();
    memset( h, 0, 16 );                     

    FLEA_CCALL(THR_flea_ecb_mode_crypt_data(ecb_ctx__pt, h, h, ecb_ctx__pt->block_length__u8));

#ifdef FLEA_HAVE_BE_ARCH_OPT
  
 //   GET_UINT32_BE( vh_a[1], h,  0  );    
 vh_a[1] = FLEA_DECODE_U32_BE(h + 0);
 vh_a[0] = FLEA_DECODE_U32_BE(h + 4);
 vl_a[1] = FLEA_DECODE_U32_BE(h + 8);
 vl_a[0] = FLEA_DECODE_U32_BE(h + 12);
    
 /*GET_UINT32_BE( vh_a[0], h,  4  );

    GET_UINT32_BE( vl_a[1], h,  8  );
    GET_UINT32_BE( vl_a[0], h,  12 );*/
#else
    vh_a[1] = flea__decode_U32_BE(h);
    vh_a[0] = flea__decode_U32_BE(h+4);
    vl_a[1] = flea__decode_U32_BE(h+8);
    vl_a[0] = flea__decode_U32_BE(h+12);
#endif

    ctx__pt->HL[16] = vl_a[0];                
    ctx__pt->HL[17] = vl_a[1];               

    ctx__pt->HH[16] = vh_a[0];
    ctx__pt->HH[17] = vh_a[1];
    
    ctx__pt->HH[0] = 0;                 
    ctx__pt->HH[1] = 0;                
    
    ctx__pt->HL[0] = 0;
    ctx__pt->HL[1] = 0;

    for( i = 4; i > 0; i >>= 1 ) 
    {
      flea_u32_t tmp_a[2];
        flea_u32_t T = (flea_u32_t) ( vl_a[0] & 1 ) * 0xe1000000UL;
        FLEA_LSHIFT_U64_AU32_LARGE(vh_a, tmp_a, 63); 
        FLEA_RSHIFT_U64_AU32_SMALL(vl_a, vl_a, 1);
        FLEA_U64_OR_AU32(vl_a, tmp_a);
        FLEA_RSHIFT_U64_AU32_SMALL(vh_a, vh_a, 1);
        vh_a[1] ^= T;

        ctx__pt->HL[2*i] = vl_a[0];
        ctx__pt->HL[2*i+1] = vl_a[1];

        ctx__pt->HH[2*i] = vh_a[0];
        ctx__pt->HH[2*i+1] = vh_a[1];
    }
    for (i = 2; i < 16; i <<= 1 ) {
        flea_u32_t * HiL_a = ctx__pt->HL + 2*i;
        flea_u32_t * HiH_a = ctx__pt->HH + 2*i;
        
        vh_a[0] = HiH_a[0];
        vh_a[1] = HiH_a[1];
        
        vl_a[0] = HiL_a[0];
        vl_a[1] = HiL_a[1];

        for( j = 1; j < i; j++ ) 
        {
            HiH_a[2*j] = vh_a[0] ^ ctx__pt->HH[2*j];
            HiH_a[2*j+1] = vh_a[1] ^ ctx__pt->HH[2*j+1];

            HiL_a[2*j] = vl_a[0] ^ ctx__pt->HL[2*j];
            HiL_a[2*j+1] = vl_a[1] ^ ctx__pt->HL[2*j+1];
        }
    }
    FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_ghash_ctx_t__start( flea_ghash_ctx_t *ctx, const flea_ecb_mode_ctx_t * ecb_ctx__pt, const flea_u8_t *iv, size_t iv_len, const flea_u8_t *add, size_t add_len
    )     
{
    flea_u8_t work_buf[16]; 
    const flea_u8_t *p;    
    size_t use_len;     
    size_t i;          

    FLEA_THR_BEG_FUNC();
    memset( ctx->y,   0x00, sizeof(ctx->y  ) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );
    ctx->len = 0;
    ctx->add_len = 0;
    ctx->pend_input_len__u8 = 0;

    if( iv_len == 12 ) 
    {              
        memcpy( ctx->y, iv, iv_len );  
        ctx->y[15] = 1;                 
    }
    else    
    {   
        memset( work_buf, 0x00, 16 );               
        PUT_UINT32_BE( iv_len * 8, work_buf, 12 ); 

        p = iv;
        while( iv_len > 0 ) 
        {
            use_len = ( iv_len < 16 ) ? iv_len : 16;
            for( i = 0; i < use_len; i++ ) ctx->y[i] ^= p[i];
            ghash_process_block( ctx, ctx->y, ctx->y );
            iv_len -= use_len;
            p += use_len;
        }
        for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
        ghash_process_block( ctx, ctx->y, ctx->y );
    }
    FLEA_CCALL(THR_flea_ecb_mode_crypt_data(ecb_ctx__pt, ctx->y, ctx->base_ectr, ecb_ctx__pt->block_length__u8));

    ctx->add_len = add_len;
    p = add;
    while( add_len > 0 ) {
        use_len = ( add_len < 16 ) ? add_len : 16;
        for( i = 0; i < use_len; i++ ) ctx->buf[i] ^= p[i];
        ghash_process_block( ctx, ctx->buf, ctx->buf );
        add_len -= use_len;
        p += use_len;
    }
    FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ghash_ctx_t__update( flea_ghash_ctx_t *ctx__pt, flea_dtl_t input_len__dtl, const flea_u8_t *input__pcu8 ) 
{
  flea_u8_t *pend_block__pu8 = ctx__pt->pend_input__bu8;

  FLEA_THR_BEG_FUNC();
  ctx__pt->len += input_len__dtl; 
  const flea_al_u8_t block_length__calu8  = 16;
  flea_al_u8_t left__alu8, to_copy__alu8, tail_len__alu8;
  flea_dtl_t nb_full_blocks__alu16, i;
  flea_al_u8_t pend_len__alu8 = ctx__pt->pend_input_len__u8;
  left__alu8 = block_length__calu8 - pend_len__alu8;
  to_copy__alu8 = FLEA_MIN(input_len__dtl, left__alu8);
  memcpy(pend_block__pu8+ pend_len__alu8, input__pcu8, to_copy__alu8);
  input__pcu8 += to_copy__alu8;
  input_len__dtl -= to_copy__alu8;
  pend_len__alu8 += to_copy__alu8;

  nb_full_blocks__alu16 = input_len__dtl / block_length__calu8;
  tail_len__alu8 = input_len__dtl % block_length__calu8;
  // TODO: DON'T NEED THE PEND BUF, CAN DIRECTLY XOR TO ->buf
  if(pend_len__alu8 == block_length__calu8)
  {
    flea__xor_bytes_in_place(ctx__pt->buf, pend_block__pu8, block_length__calu8); 
    ghash_process_block( ctx__pt, ctx__pt->buf, ctx__pt->buf );
    pend_len__alu8 = 0;
  }
  for(i = 0; i < nb_full_blocks__alu16; i++)
  {
    flea__xor_bytes_in_place(ctx__pt->buf, input__pcu8, block_length__calu8); 
    ghash_process_block( ctx__pt, ctx__pt->buf, ctx__pt->buf );
    input__pcu8 += block_length__calu8;
  }
  if(tail_len__alu8 != 0)
  {
    memcpy(pend_block__pu8, input__pcu8, tail_len__alu8);
    pend_len__alu8 = tail_len__alu8;
  }
  ctx__pt->pend_input_len__u8 = pend_len__alu8;
  FLEA_THR_FIN_SEC_empty();
}

void flea_ghash_ctx_t__finish( flea_ghash_ctx_t *ctx__pt, 
                flea_u8_t *tag,         
                size_t tag_len )    
{
  flea_u8_t work_buf[16];
  flea_u64_t orig_len     = ctx__pt->len * 8;
  flea_u32_t orig_add_len__u32 = ctx__pt->add_len * 8;
  if(ctx__pt->pend_input_len__u8)
  {
    flea__xor_bytes_in_place(ctx__pt->buf, ctx__pt->pend_input__bu8, ctx__pt->pend_input_len__u8); 
    ghash_process_block( ctx__pt, ctx__pt->buf, ctx__pt->buf );    
  }
  if( tag_len != 0 ) memcpy( tag, ctx__pt->base_ectr, tag_len );

  if( orig_len || orig_add_len__u32 ) {
    memset( work_buf, 0x00, 16 );

    PUT_UINT32_BE( 0 , work_buf, 0  );
    PUT_UINT32_BE( ( orig_add_len__u32       ), work_buf, 4  );
    PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
    PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

    flea__xor_bytes_in_place(ctx__pt->buf, work_buf, 16);
    ghash_process_block( ctx__pt, ctx__pt->buf, ctx__pt->buf );
    flea__xor_bytes_in_place(tag, ctx__pt->buf, tag_len);
  }
}

