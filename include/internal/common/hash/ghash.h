
#ifndef _flea_gcm__H_
#define _flea_gcm__H_

#include "flea/error_handling.h"
#include "flea/types.h"
#include "flea/block_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

  // TODO: REPLACE
#define ENCRYPT         1       // specify whether we're encrypting
#define DECRYPT         0       // or decrypting
// TODO: REMOVE U64BIT, also from gcm source
// ADD ECB-MODE CRYPT NOTHROW
typedef struct {
    //int mode;               // cipher direction: encrypt/decrypt
    flea_u64_t len;           // cipher data length processed so far
    flea_u64_t add_len;       // total add data length
    flea_u32_t HL[32];        // precalculated lo-half HTable
    flea_u32_t HH[32];        // precalculated hi-half HTable
    flea_u8_t base_ectr[16];    // first counter-mode cipher output for tag
    flea_u8_t y[16];            // the current cipher-input IV|Counter value
    flea_u8_t buf[16];          // buf working value
    flea_u8_t pend_input__bu8[16];
    flea_u8_t pend_input_len__u8;
    //aes_context aes_ctx;    // cipher context used
} flea_ghash_ctx_t;

flea_err_t THR_flea_ghash_ctx_t__setkey( flea_ghash_ctx_t *ctx__pt,   // pointer to caller-provided gcm context
    const flea_ecb_mode_ctx_t *ecb_ctx__pt);

flea_err_t THR_flea_ghash_ctx_t__start( flea_ghash_ctx_t *ctx,    // pointer to user-provided GCM context
              const flea_ecb_mode_ctx_t * ecb_ctx__pt,
               const flea_u8_t *iv,     // pointer to initialization vector
               size_t iv_len,       // IV length in bytes (should == 12)
               const flea_u8_t *add,    // ptr to additional AEAD data (NULL if none)
               size_t add_len
    );

flea_err_t THR_flea_ghash_ctx_t__update( flea_ghash_ctx_t *ctx,       // pointer to user-provided GCM context
                flea_dtl_t length,          // length, in bytes, of data to process
                const flea_u8_t *input     // pointer to source data
                //flea_u8_t *output,
               // int mode
                );

void flea_ghash_ctx_t__finish( flea_ghash_ctx_t *ctx,   // pointer to user-provided GCM context
                flea_u8_t *tag,         // pointer to buffer which receives the tag
                size_t tag_len );    // length, in bytes, of the tag-receiving buf
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
