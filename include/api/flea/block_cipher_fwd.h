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
typedef enum { flea_des_single, flea_tdes_2key, flea_tdes_3key, flea_desx, flea_aes128, flea_aes192,
               flea_aes256 } flea_block_cipher_id_t;

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
