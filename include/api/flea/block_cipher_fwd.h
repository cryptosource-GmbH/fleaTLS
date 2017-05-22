/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_block_cipher_fwd__H_
#define _flea_block_cipher_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Forward declaration for ecb_mode_ctx_t
 */
struct struct_flea_ecb_mode_ctx_t;

/**
 *  ECB mode context type.
 */
typedef struct struct_flea_ecb_mode_ctx_t flea_ecb_mode_ctx_t;

/**
 * supported block ciphers.
 */
typedef enum { flea_des_single = 1, flea_tdes_2key = 2, flea_tdes_3key = 3, flea_desx = 4, flea_aes128 = 5,
               flea_aes192     = 6,
               flea_aes256     = 7 } flea_block_cipher_id_t;

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
