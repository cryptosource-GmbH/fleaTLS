
#include "flea/ae.h"
#include "flea/bin_utils.h"
#include "internal/common/hash/ghash.h"
#include "flea/error_handling.h"

static const flea_u16_t ghash_lo[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0  };

/*
 * Platform Endianness Neutralizing Load and Store Macro definitions
 * GCM wants platform-neutral Big Endian (BE) byte ordering
 */
#define GET_UINT32_BE(n,b,i) {                      \
    (n) = ( (flea_u32_t) (b)[(i)    ] << 24 )         \
        | ( (flea_u32_t) (b)[(i) + 1] << 16 )         \
        | ( (flea_u32_t) (b)[(i) + 2] <<  8 )         \
        | ( (flea_u32_t) (b)[(i) + 3]       ); }

#define PUT_UINT32_BE(n,b,i) {                      \
    (b)[(i)    ] = (flea_u8_t) ( (n) >> 24 );   \
    (b)[(i) + 1] = (flea_u8_t) ( (n) >> 16 );   \
    (b)[(i) + 2] = (flea_u8_t) ( (n) >>  8 );   \
    (b)[(i) + 3] = (flea_u8_t) ( (n)       ); }


/******************************************************************************
 *
 *  GCM_INITIALIZE
 *
 *  Must be called once to initialize the GCM library.
 *
 *  At present, this only calls the AES keygen table generator, which expands
 *  the AES keying tables for use. This is NOT A THREAD-SAFE function, so it
 *  MUST be called during system initialization before a multi-threading
 *  environment is running.
 *
 ******************************************************************************/
/*int gcm_initialize( void )
{
    aes_init_keygen_tables();
    return( 0 );
}*/


/******************************************************************************
 *
 *  GCM_MULT
 *
 *  Performs a GHASH operation on the 128-bit input vector 'x', setting
 *  the 128-bit output vector to 'x' times H using our precomputed tables.
 *  'x' and 'output' are seen as elements of GCM's GF(2^128) Galois field.
 *
 ******************************************************************************/

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

#define FLEA_U64_TO_AU32(u64, au32) \
do { \
  au32[0] = u64; \
  au32[1] = u64 >> 32; \
}while(0)

#define FLEA_AU32_TO_U64(au32, u64) \
do { \
  u64 = au32[0] | ((flea_u64_t) au32[1] << 32); \
}while(0)

#define FLEA_U64_OR_AU32(au32_in_out, au32_in) \
  do { \
    au32_in_out[0] |= au32_in[0]; \
    au32_in_out[1] |= au32_in[1]; \
  }while(0)

static void gcm_mult( flea_ghash_ctx_t *ctx__pt,     // pointer to established context
                      const flea_u8_t x[16],    // pointer to 128-bit input vector
                      flea_u8_t output[16] )    // pointer to 128-bit output vector
{
    int i;
    flea_u8_t lo, hi, rem;
   // flea_u64_t zh, zl, tmp;
    flea_u32_t zl_a[2];
    flea_u32_t zh_a[2];
    flea_u32_t tmp_a[2];
    lo = (flea_u8_t)( x[15] & 0x0f );
    hi = (flea_u8_t)( x[15] >> 4 );
    //zh = ctx__pt->HH[lo];
    //zh = ctx__pt->HH[2*lo] | (flea_u64_t) ctx__pt->HH[2*lo+1] << 32;
    zh_a[0] = ctx__pt->HH[2*lo];
    zh_a[1] = ctx__pt->HH[2*lo+1];

    //printf("from HH: zh = %016llx\n", zh);

    //zl = ctx__pt->HL[lo];
    //zl = ctx__pt->HL[2*lo] |  (flea_u64_t) ctx__pt->HL[2*lo+1] << 32;
    zl_a[0] = ctx__pt->HL[2*lo];
    zl_a[1] = ctx__pt->HL[2*lo+1];
    
    //printf("from HL: zl = %016llx\n", zl);
  
    //flea_u32_t zhl, zhh, zll, zlh;
    for( i = 15; i >= 0; i-- ) 
    {
        lo = (flea_u8_t) ( x[i] & 0x0f );
        hi = (flea_u8_t) ( x[i] >> 4 );

        if( i != 15 ) 
        {
            //rem = (flea_u8_t) ( zl & 0x0f );
            rem = (flea_u8_t) ( zl_a[0] & 0x0f );
            //zl = ( zh << 60 ) | ( zl >> 4 );
       
            /*FLEA_U64_TO_AU32(zl, zl_a); 
            FLEA_U64_TO_AU32(zh, zh_a); */

            FLEA_LSHIFT_U64_AU32_LARGE(zh_a, tmp_a, 60);
            FLEA_RSHIFT_U64_AU32_SMALL(zl_a, zl_a, 4);
            zl_a[0] |= tmp_a[0];
            zl_a[1] |= tmp_a[1];

            
            //zl = tmp | ( zl >> 4 );
            
            //zl = (flea_u64_t)zlh << 32 | zll | zl >> 4;
        
        
            //zh = ( zh >> 4 );
            //FLEA_RSHIFT_U64_AU32_SMALL(zl_a, zl_a, 4);
            FLEA_RSHIFT_U64_AU32_SMALL(zh_a, zh_a, 4);

            //zh ^= (flea_u64_t) last4[rem] << 48;
            tmp_a[0] = ghash_lo[rem];
            tmp_a[1] = 0;
            FLEA_LSHIFT_U64_AU32_LARGE(tmp_a, tmp_a, 48);
            zh_a[0] ^= tmp_a[0];
            zh_a[1] ^= tmp_a[1];


            //zh ^= ctx__pt->HH[lo];
            //zh ^= ctx__pt->HH[2*lo] | (flea_u64_t) ctx__pt->HH[2*lo+1] << 32;
            zh_a[0] ^= ctx__pt->HH[2*lo];
            zh_a[1] ^= ctx__pt->HH[2*lo+1];

            //zl ^= ctx__pt->HL[lo];
            //zl ^= ctx__pt->HL[2*lo] | (flea_u64_t) ctx__pt->HL[2*lo+1] << 32;
            zl_a[0] ^= ctx__pt->HL[2*lo];
            zl_a[1] ^= ctx__pt->HL[2*lo+1];


        }
        //rem = (flea_u8_t) ( zl & 0x0f );
        rem = (flea_u8_t) ( zl_a[0] & 0x0f );
        //zl = ( zh << 60 ) | ( zl >> 4 );

        FLEA_LSHIFT_U64_AU32_LARGE(zh_a, tmp_a, 60);
        FLEA_RSHIFT_U64_AU32_SMALL(zl_a, zl_a, 4);
        FLEA_U64_OR_AU32(zl_a, tmp_a);
//==============
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
#if 0
        zh = ( zh >> 4 );
        //printf("rem = %u\n", rem);
        zh ^= (flea_u64_t) last4[rem] << 48;
      
        //zh ^= ctx__pt->HH[hi];
        zh ^= ctx__pt->HH[2*hi] | (flea_u64_t) ctx__pt->HH[2*hi+1] << 32;
       
        //zl ^= ctx__pt->HL[hi];
        zl ^= ctx__pt->HL[2*hi] |  (flea_u64_t) ctx__pt->HL[2*hi+1] << 32;
#endif 
    }
/*  PUT_UINT32_BE( zh >> 32, output, 0 );
    PUT_UINT32_BE( zh, output, 4 );
    PUT_UINT32_BE( zl >> 32, output, 8 );
    PUT_UINT32_BE( zl, output, 12 );*/
    PUT_UINT32_BE( zh_a[1], output, 0 );
    PUT_UINT32_BE( zh_a[0], output, 4 );
    PUT_UINT32_BE( zl_a[1], output, 8 );
    PUT_UINT32_BE( zl_a[0], output, 12 );
}
/******************************************************************************
 *
 *  GCM_SETKEY
 *
 *  This is called to set the AES-GCM key. It initializes the AES key
 *  and populates the gcm context's pre-calculated HTables.
 *
 ******************************************************************************/
flea_err_t THR_flea_ghash_ctx_t__setkey( flea_ghash_ctx_t *ctx__pt,   // pointer to caller-provided gcm context
    const flea_ecb_mode_ctx_t *ecb_ctx__pt
                ) // must be 128, 192 or 256
{
    int i, j;
    //flea_u64_t hi, lo;
    //flea_u32_t hi_a[2], lo_a[2];
    //flea_u64_t vl, vh;
    flea_u32_t vl_a[2], vh_a[2];
    flea_u8_t h[16];

    FLEA_THR_BEG_FUNC();
    //memset( ctx, 0, sizeof(flea_ghash_ctx_t) );  // zero caller-provided GCM context
    memset( h, 0, 16 );                     // initialize the block to encrypt

    // encrypt the null 128-bit block to generate a key-based value
    // which is then used to initialize our GHASH lookup tables
    /*if(( ret = aes_setkey( &ctx->aes_ctx, ENCRYPT, key, keysize )) != 0 )
        return( ret );*/
    
    /*if(( ret = aes_cipher( &ctx->aes_ctx, h, h )) != 0 )
        return( ret );*/
    FLEA_CCALL(THR_flea_ecb_mode_crypt_data(ecb_ctx__pt, h, h, ecb_ctx__pt->block_length__u8));

    //GET_UINT32_BE( hi, h,  0  );    // pack h as two 64-bit ints, big-endian
    GET_UINT32_BE( vh_a[1], h,  0  );    // pack h as two 64-bit ints, big-endian
    //GET_UINT32_BE( lo_a[0], h,  4  );
    GET_UINT32_BE( vh_a[0], h,  4  );
    //vh = (flea_u64_t) hi << 32 | lo;

    //GET_UINT32_BE( hi, h,  8  );
    GET_UINT32_BE( vl_a[1], h,  8  );
    //GET_UINT32_BE( lo, h,  12 );
    GET_UINT32_BE( vl_a[0], h,  12 );
    //vl = (flea_u64_t) hi << 32 | lo;

    //ctx__pt->HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
    ctx__pt->HL[16] = vl_a[0];                // 8 = 1000 corresponds to 1 in GF(2^128)
    ctx__pt->HL[17] = vl_a[1];                // 8 = 1000 corresponds to 1 in GF(2^128)

    //ctx__pt->HH[8] = vh;
    ctx__pt->HH[16] = vh_a[0];
    ctx__pt->HH[17] = vh_a[1];
    
    //ctx__pt->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
    ctx__pt->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
    ctx__pt->HH[1] = 0;                 // 0 corresponds to 0 in GF(2^128)
    
    //ctx__pt->HL[0] = 0;
    ctx__pt->HL[0] = 0;
    ctx__pt->HL[1] = 0;

    for( i = 4; i > 0; i >>= 1 ) 
    {
      flea_u32_t tmp_a[2];
        flea_u32_t T = (flea_u32_t) ( vl_a[0] & 1 ) * 0xe1000000UL;
        //vl  = ( vh << 63 ) | ( vl >> 1 );
        FLEA_LSHIFT_U64_AU32_LARGE(vh_a, tmp_a, 63); 
        FLEA_RSHIFT_U64_AU32_SMALL(vl_a, vl_a, 1);
        FLEA_U64_OR_AU32(vl_a, tmp_a);
        //vh  = ( vh >> 1 ) ^ ( (flea_u64_t) T << 32);
        FLEA_RSHIFT_U64_AU32_SMALL(vh_a, vh_a, 1);
        vh_a[1] ^= T;

        //ctx__pt->HL[i] = vl;
        ctx__pt->HL[2*i] = vl_a[0];
        ctx__pt->HL[2*i+1] = vl_a[1];

        //ctx__pt->HH[i] = vh;
        ctx__pt->HH[2*i] = vh_a[0];
        ctx__pt->HH[2*i+1] = vh_a[1];
    }
    for (i = 2; i < 16; i <<= 1 ) {
        //flea_u64_t *HiL = ctx__pt->HL + i, *HiH = ctx__pt->HH + i;
        flea_u32_t * HiL_a = ctx__pt->HL + 2*i;
        flea_u32_t * HiH_a = ctx__pt->HH + 2*i;
        
        //vh = *HiH;
        vh_a[0] = HiH_a[0];
        vh_a[1] = HiH_a[1];
        
        //vl = *HiL;
        vl_a[0] = HiL_a[0];
        vl_a[1] = HiL_a[1];

        for( j = 1; j < i; j++ ) 
        {
            //HiH[j] = vh ^ ctx__pt->HH[j];
            HiH_a[2*j] = vh_a[0] ^ ctx__pt->HH[2*j];
            HiH_a[2*j+1] = vh_a[1] ^ ctx__pt->HH[2*j+1];

            //HiL[j] = vl ^ ctx__pt->HL[j];
            HiL_a[2*j] = vl_a[0] ^ ctx__pt->HL[2*j];
            HiL_a[2*j+1] = vl_a[1] ^ ctx__pt->HL[2*j+1];
        }
    }
    FLEA_THR_FIN_SEC_empty();
}


/******************************************************************************
 *
 *    GCM processing occurs four phases: SETKEY, START, UPDATE and FINISH.
 *
 *  SETKEY: 
 *  
 *   START: Sets the Encryption/Decryption mode.
 *          Accepts the initialization vector and additional data.
 *
 *  UPDATE: Encrypts or decrypts the plaintext or ciphertext.
 *
 *  FINISH: Performs a final GHASH to generate the authentication tag.
 *
 ******************************************************************************
 *
 *  GCM_START
 *
 *  Given a user-provided GCM context, this initializes it, sets the encryption
 *  mode, and preprocesses the initialization vector and additional AEAD data.
 *
 ******************************************************************************/
flea_err_t THR_flea_ghash_ctx_t__start( flea_ghash_ctx_t *ctx,    // pointer to user-provided GCM context
              const flea_ecb_mode_ctx_t * ecb_ctx__pt,
               //int mode,            // GCM_ENCRYPT or GCM_DECRYPT
               const flea_u8_t *iv,     // pointer to initialization vector
               size_t iv_len,       // IV length in bytes (should == 12)
               const flea_u8_t *add,    // ptr to additional AEAD data (NULL if none)
               size_t add_len
    )     // length of additional AEAD data (bytes)
{
    flea_u8_t work_buf[16]; // XOR source built from provided IV if len != 16
    const flea_u8_t *p;     // general purpose array pointer
    size_t use_len;     // byte count to process, up to 16 bytes
    size_t i;           // local loop iterator

    // since the context might be reused under the same key
    // we zero the working buffers for this next new process
    FLEA_THR_BEG_FUNC();
    memset( ctx->y,   0x00, sizeof(ctx->y  ) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );
    ctx->len = 0;
    ctx->add_len = 0;
    ctx->pend_input_len__u8 = 0;
    //ctx->mode = mode;               // set the GCM encryption/decryption mode
    //ctx->aes_ctx.mode = ENCRYPT;    // GCM *always* runs AES in ENCRYPTION mode

    if( iv_len == 12 ) {                // GCM natively uses a 12-byte, 96-bit IV
        memcpy( ctx->y, iv, iv_len );   // copy the IV to the top of the 'y' buff
        ctx->y[15] = 1;                 // start "counting" from 1 (not 0)
    }
    else    // if we don't have a 12-byte IV, we GHASH whatever we've been given
    {   
        memset( work_buf, 0x00, 16 );               // clear the working buffer
        PUT_UINT32_BE( iv_len * 8, work_buf, 12 );  // place the IV into buffer

        p = iv;
        while( iv_len > 0 ) {
            use_len = ( iv_len < 16 ) ? iv_len : 16;
            for( i = 0; i < use_len; i++ ) ctx->y[i] ^= p[i];
            gcm_mult( ctx, ctx->y, ctx->y );
            iv_len -= use_len;
            p += use_len;
        }
        for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
        gcm_mult( ctx, ctx->y, ctx->y );
    }
    /*if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ctx->base_ectr ) ) != 0 )
        return( ret );*/
    FLEA_CCALL(THR_flea_ecb_mode_crypt_data(ecb_ctx__pt, ctx->y, ctx->base_ectr, ecb_ctx__pt->block_length__u8));

    ctx->add_len = add_len;
    p = add;
    while( add_len > 0 ) {
        use_len = ( add_len < 16 ) ? add_len : 16;
        for( i = 0; i < use_len; i++ ) ctx->buf[i] ^= p[i];
        gcm_mult( ctx, ctx->buf, ctx->buf );
        add_len -= use_len;
        p += use_len;
    }
    FLEA_THR_FIN_SEC_empty();
}

/******************************************************************************
 *
 *  GCM_UPDATE
 *
 *  This is called once or more to process bulk plaintext or ciphertext data.
 *  We give this some number of bytes of input and it returns the same number
 *  of output bytes. If called multiple times (which is fine) all but the final
 *  invocation MUST be called with length mod 16 == 0. (Only the final call can
 *  have a partial block length of < 128 bits.)
 *
 ******************************************************************************/
flea_err_t THR_flea_ghash_ctx_t__update( flea_ghash_ctx_t *ctx__pt,       // pointer to user-provided GCM context
                flea_dtl_t input_len__dtl,          // length, in bytes, of data to process
                const flea_u8_t *input__pcu8     // pointer to source data
                //flea_u8_t *output,
    )         // pointer to destination data
{
    //flea_u8_t ectr[16];     // counter-mode cipher output for XORing
    //size_t use_len;     // byte count to process, up to 16 bytes
    //size_t i;           // local loop iterator
    flea_u8_t *pend_block__pu8 = ctx__pt->pend_input__bu8;
    
FLEA_THR_BEG_FUNC();
    ctx__pt->len += input_len__dtl; // bump the GCM context's running length count
// TODO: REPLACE 16 BY BLOCKLENGTH ??
#if 0
    while( length > 0 ) 
    {
        // clamp the length to process at 16 bytes
        use_len = ( length < 16 ) ? length : 16;

        // increment the context's 128-bit IV||Counter 'y' vector
        for( i = 16; i > 12; i-- ) if( ++ctx->y[i - 1] != 0 ) break;

        {
          unsigned k;
          printf("gcm ctr block = ");
          for( k = 0; k < 16; k++) {if(k % 16 == 0) { printf("\n");}printf("%02x ", ctx->y[k]); } printf("\n");
        }
        

        // encrypt the context's 'y' vector under the established key
        //if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ectr ) ) != 0 )
         //   return( ret );
        
    FLEA_CCALL(THR_flea_ecb_mode_crypt_data(&ctx->ctr_ctx__t.cipher_ctx__t, ctx->y, ectr, ctx->ctr_ctx__t.cipher_ctx__t.block_length__u8));

        {
          unsigned k;
        printf("gcm ectr block = ");
    for( k = 0; k < 16; k++) {if(k % 16 == 0) { printf("\n");}printf("%02x ", ectr[k]); } printf("\n");
        }
        {
          unsigned k;
        printf("aes input block = ");
    for( k = 0; k < use_len; k++) {if(k % 16 == 0) { printf("\n");}printf("%02x ", input[k]); } printf("\n");
        }

        // encrypt or decrypt the input to the output
        for( i = 0; i < use_len; i++ ) 
        {
            // XOR the cipher's ouptut vector (ectr) with our input
            
        
            output[i] = (flea_u8_t) ( ectr[i] ^ input[i] );
            // now we mix in our data into the authentication hash.
            // if we're ENcrypting we XOR in the post-XOR (output) results,
            // but if we're DEcrypting we XOR in the input data
            if( mode == ENCRYPT )  ctx->buf[i] ^= output[i];
            else                        ctx->buf[i] ^= input[i];
        }
        {
          unsigned k;
          printf("aes output block = ");
          for( k = 0; k < use_len; k++) {if(k % 16 == 0) { printf("\n");}printf("%02x ", output[k]); } printf("\n");
        }
        gcm_mult( ctx, ctx->buf, ctx->buf );    // perform a GHASH operation

        length -= use_len;  // drop the remaining byte count to process
        input  += use_len;  // bump our input pointer forward
        output += use_len;  // bump our output pointer forward
    }
#endif
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
      //ctx__pt->primitive_specific_ctx__u.cmac_specific__t.cipher_ctx__t.block_crypt_f(&ctx__pt->primitive_specific_ctx__u.cmac_specific__t.cipher_ctx__t, block__pu8, block__pu8);
      flea__xor_bytes_in_place(ctx__pt->buf, pend_block__pu8, block_length__calu8); 
      gcm_mult( ctx__pt, ctx__pt->buf, ctx__pt->buf );    // perform a GHASH operation
      pend_len__alu8 = 0;
    }
    for(i = 0; i < nb_full_blocks__alu16; i++)
    {
      flea__xor_bytes_in_place(ctx__pt->buf, input__pcu8, block_length__calu8); 
      gcm_mult( ctx__pt, ctx__pt->buf, ctx__pt->buf );    // perform a GHASH operation
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

void flea_ghash_ctx_t__finish( flea_ghash_ctx_t *ctx__pt,   // pointer to user-provided GCM context
                flea_u8_t *tag,         // pointer to buffer which receives the tag
                size_t tag_len )    // length, in bytes, of the tag-receiving buf
{
  flea_u8_t work_buf[16];
  flea_u64_t orig_len     = ctx__pt->len * 8;
  flea_u64_t orig_add_len = ctx__pt->add_len * 8;
  size_t i;
  if(ctx__pt->pend_input_len__u8)
  {
    flea__xor_bytes_in_place(ctx__pt->buf, ctx__pt->pend_input__bu8, ctx__pt->pend_input_len__u8); 
    gcm_mult( ctx__pt, ctx__pt->buf, ctx__pt->buf );    // perform a GHASH operation
  }
  if( tag_len != 0 ) memcpy( tag, ctx__pt->base_ectr, tag_len );

  if( orig_len || orig_add_len ) {
    memset( work_buf, 0x00, 16 );

    PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
    PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
    PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
    PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

    //for( i = 0; i < 16; i++ ) ctx__pt->buf[i] ^= work_buf[i];
    flea__xor_bytes_in_place(ctx__pt->buf, work_buf, 16);
    gcm_mult( ctx__pt, ctx__pt->buf, ctx__pt->buf );
    //for( i = 0; i < tag_len; i++ ) tag[i] ^= ctx__pt->buf[i];
    flea__xor_bytes_in_place(tag, ctx__pt->buf, tag_len);
  }
}


/******************************************************************************
 *
 *  GCM_CRYPT_AND_TAG
 *
 *  This either encrypts or decrypts the user-provided data and, either
 *  way, generates an authentication tag of the requested length. It must be
 *  called with a GCM context whose key has already been set with GCM_SETKEY.
 *
 *  The user would typically call this explicitly to ENCRYPT a buffer of data
 *  and optional associated data, and produce its an authentication tag.
 *
 *  To reverse the process the user would typically call the companion
 *  GCM_AUTH_DECRYPT function to decrypt data and verify a user-provided
 *  authentication tag.  The GCM_AUTH_DECRYPT function calls this function
 *  to perform its decryption and tag generation, which it then compares.
 *
 ******************************************************************************/
#if 0
flea_err_t THR_flea_gcm_crypt_and_tag(
        flea_ghash_ctx_t *ctx,       // gcm context with key already setup
        int mode,               // cipher direction: GCM_ENCRYPT or GCM_DECRYPT
        const flea_u8_t *iv,        // pointer to the 12-byte initialization vector
        size_t iv_len,          // byte length if the IV. should always be 12
        const flea_u8_t *add,       // pointer to the non-ciphered additional data
        size_t add_len,         // byte length of the additional AEAD data
        const flea_u8_t *input,     // pointer to the cipher data source
        flea_u8_t *output,          // pointer to the cipher data destination
        size_t length,          // byte length of the cipher data
        flea_u8_t *tag,             // pointer to the tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{   /*
       assuming that the caller has already invoked gcm_setkey to
       prepare the gcm context with the keying material, we simply
       invoke each of the three GCM sub-functions in turn...
       */
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_gcm_start  ( ctx, iv, iv_len, add, add_len ));
  FLEA_CCALL(THR_flea_gcm_update ( ctx, length, input, output, mode ));
  gcm_finish( ctx, tag, tag_len );
  FLEA_THR_FIN_SEC_empty();
}
#endif


/******************************************************************************
 *
 *  GCM_AUTH_DECRYPT
 *
 *  This DECRYPTS a user-provided data buffer with optional associated data.
 *  It then verifies a user-supplied authentication tag against the tag just
 *  re-created during decryption to verify that the data has not been altered.
 *
 *  This function calls GCM_CRYPT_AND_TAG (above) to perform the decryption
 *  and authentication tag generation.
 *
 ******************************************************************************/
#if 0
flea_err_t THR_flea_gcm_auth_decrypt(
        flea_ghash_ctx_t *ctx,       // gcm context with key already setup
        const flea_u8_t *iv,        // pointer to the 12-byte initialization vector
        size_t iv_len,          // byte length if the IV. should always be 12
        const flea_u8_t *add,       // pointer to the non-ciphered additional data
        size_t add_len,         // byte length of the additional AEAD data
        const flea_u8_t *input,     // pointer to the cipher data source
        flea_u8_t *output,          // pointer to the cipher data destination
        size_t length,          // byte length of the cipher data
        const flea_u8_t *tag,       // pointer to the tag to be authenticated
        size_t tag_len )        // byte length of the tag <= 16
{
  flea_u8_t check_tag[16];        // the tag generated and returned by decryption
  int diff;                   // an ORed flag to detect authentication errors
  size_t i;                   // our local iterator
  /*
     we use GCM_DECRYPT_AND_TAG (above) to perform our decryption
     (which is an identical XORing to reverse the previous one)
     and also to re-generate the matching authentication tag
     */
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_gcm_crypt_and_tag(  ctx, DECRYPT, iv, iv_len, add, add_len,
        input, output, length, check_tag, tag_len ));

  // now we verify the authentication tag in 'constant time'
  for( diff = 0, i = 0; i < tag_len; i++ )
  {
    diff |= tag[i] ^ check_tag[i];
  }

  if( diff != 0 ) 
  {                   // see whether any bits differed?
    memset( output, 0, length );    // if so... wipe the output data
    FLEA_THROW("GCM verification failed", FLEA_ERR_INV_MAC);
  }
  FLEA_THR_FIN_SEC_empty();
}
#endif
