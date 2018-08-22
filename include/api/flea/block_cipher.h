/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_block_cipher__H_
# define _flea_block_cipher__H_

# include "internal/common/default.h"
# include "flea/types.h"
# include "internal/common/block_cipher/block_cipher_int.h"

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_AES256_KEY_BYTE_LENGTH 32
# define FLEA_AES192_KEY_BYTE_LENGTH 24
# define FLEA_AES128_KEY_BYTE_LENGTH 16
# define FLEA_AES_BLOCK_LENGTH       16

# ifdef FLEA_HEAP_MODE
#  define flea_ecb_mode_ctx_t__INIT(__p) FLEA_ZERO_STRUCT(__p)
#  define flea_ctr_mode_ctx_t__INIT(__p) FLEA_ZERO_STRUCT(__p)
#  define flea_cbc_mode_ctx_t__INIT(__p) FLEA_ZERO_STRUCT(__p)
# else // ifdef FLEA_HEAP_MODE
#  define flea_ecb_mode_ctx_t__INIT(__p) do {(__p)->config__pt = NULL;} while(0)
#  define flea_ctr_mode_ctx_t__INIT(__p) do {flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t);} while(0)
#  define flea_cbc_mode_ctx_t__INIT(__p) do {flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t);} while(0)
# endif /* ifdef FLEA_HEAP_MODE */

/**
 * Find out the block byte size of a given cipher.
 *
 * @param id the id of the block cipher
 *
 * @return the block byte size
 */
flea_al_u8_t flea_block_cipher__get_block_size(flea_block_cipher_id_e id);

/**
 * Find out the key byte size of a given cipher.
 *
 * @param id the id of the block cipher
 *
 * @return the key byte size
 */
flea_al_u8_t flea_block_cipher__get_key_size(flea_block_cipher_id_e id);

/**
 * Create an ECB mode context.
 *
 * @param ctx pointer to the context object to create
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param dir cipher direction (either flea_encrypt or flea_decrypt)
 */
flea_err_e THR_flea_ecb_mode_ctx_t__ctor(
  flea_ecb_mode_ctx_t*   ctx,
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u16_t          key_len,
  flea_cipher_dir_e      dir
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Destroy an ECB mode context.
 *
 * @param ctx pointer to the context object to destroy
 */
void flea_ecb_mode_ctx_t__dtor(flea_ecb_mode_ctx_t* ctx);

/**
 * Encrypt or decrypt (depending on the dir argument provided in the creation of
 * ctx) data.
 *
 * @param ctx pointer to the context object to use
 * @param input the input data
 * @param output the output data, may be equal to input (in-place encryption/decryption), but partial overlapping is not allowed
 * @param input_output_len the length of input and output. Must be a multiple of
 * the underlying cipher's block size.
 */
flea_err_e THR_flea_ecb_ctx_t__crypt_data(
  const flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*           input,
  flea_u8_t*                 output,
  flea_dtl_t                 input_output_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Create a CTR mode cipher context. The following uses a notation with
 * ascending array indexes from left to right. The operation starts with a
 * counter block formed by  (nonce || 0...0). The nonce may expand over the full
 * block length of the underlying cipher.  The size of the counter that is
 * actually incremented is defined by ctr_len. This many bytes from the right
 * will be incremented as a big endian integer modulo 2^(8*ctr_len).  Thereby
 * the counter may well expand into the nonce area.  This object can be used for
 * either encryption or decryption, as these operations are identical in CTR
 * mode.
 *
 * @param ctx pointer to the context to create
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param nonce pointer to the nonce value
 * @param nonce_len length of nonce, may range from 0 to the underlying cipher's * block size in bytes
 * @param ctr_len the length of counter window within the counter block, which is interpreted as a BE integer
 * ranging from position [max](LSB) to [max - ctr_len](MSB). Only this range
 */
flea_err_e THR_flea_ctr_mode_ctx_t__ctor(
  flea_ctr_mode_ctx_t*   ctx,
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u8_t           key_len,
  const flea_u8_t*       nonce,
  flea_al_u8_t           nonce_len,
  flea_al_u8_t           ctr_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Destroy a CTR mode context object.
 *
 * @param ctx pointer to the context object to destroy
 */
void flea_ctr_mode_ctx_t__dtor(flea_ctr_mode_ctx_t* ctx);

/**
 * Encrypt or decrypt data in counter mode (the counter mode operation for
 * encryption and decryption is exactly the same) using a context object.
 * The internal counter state in ctx is updated according to the amount of processed data.
 *
 * @param ctx pointer to the context object to use
 * @param input the input data
 * @param output the output data
 * @param input_output_len the length of input and output data
 */
void flea_ctr_mode_ctx_t__crypt(
  flea_ctr_mode_ctx_t* ctx,
  const flea_u8_t*     input,
  flea_u8_t*           output,
  flea_dtl_t           input_output_len
);

/**
 * Encrypt/decrypt data in counter mode without using a context object.
 * The counter starts at zero. For the specification of the usage of the nonce
 * and the ctr_len parameters refer to THR_flea_ctr_mode_ctx_t__ctor().
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param nonce pointer to the nonce value
 * @param nonce_len length of nonce, may range from 0 to the underlying cipher's * block size in bytes
 * @param input the input data
 * @param output the output data
 * @param input_output_len the length of input and output data
 * @param ctr_len the length of counter window within the counter block, which is interpreted as a BE integer
 * ranging from position [max](LSB) to [max - ctr_len](MSB)
 */
flea_err_e THR_flea_ctr_mode_crypt_data(
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u16_t          key_len,
  const flea_u8_t*       nonce,
  flea_al_u8_t           nonce_len,
  const flea_u8_t*       input,
  flea_u8_t*             output,
  flea_dtl_t             input_output_len,
  flea_al_u8_t           ctr_len
) FLEA_ATTRIB_UNUSED_RESULT;


/**
 * Create a CBC mode context object.
 *
 * @param ctx pointer to the context object to create
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param dir cipher direction (either flea_encrypt or flea_decrypt)
 */
flea_err_e THR_flea_cbc_mode_ctx_t__ctor(
  flea_cbc_mode_ctx_t*   ctx,
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u8_t           key_len,
  const flea_u8_t*       iv,
  flea_al_u8_t           iv_len,
  flea_cipher_dir_e      dir
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Destroy a CBC mode context object.
 *
 * @param ctx pointer to the context object to destroy
 */
void flea_cbc_mode_ctx_t__dtor(flea_cbc_mode_ctx_t* ctx);

/**
 * Encrypt or decrypt (depending on the dir argument provided in the creation of
 * ctx) data in using a CBC mode context object.
 *
 * @param ctx pointer to the context object to use
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input, but partial overlapping is not allowed
 * @param input_output_len the length of input and output. Must be a multiple of
 * the underlying cipher's block size.
 */
flea_err_e THR_flea_cbc_mode_ctx_t__crypt(
  flea_cbc_mode_ctx_t* ctx,
  const flea_u8_t*     input,
  flea_u8_t*           output,
  flea_dtl_t           input_output_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Encrypt or decrypt data in CBC mode without using a context object.
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param dir cipher direction (either flea_encrypt or flea_decrypt)
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input, but partial overlapping is not allowed
 * @param input_output_len the length of input and output
 */
flea_err_e THR_flea_cbc_mode__crypt_data(
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u8_t           key_len,
  const flea_u8_t*       iv,
  flea_al_u8_t           iv_len,
  flea_cipher_dir_e      dir,
  const flea_u8_t*       input,
  flea_u8_t*             output,
  flea_dtl_t             input_output_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Encrypt data in CBC mode without using a context object.
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input, but partial overlapping is not allowed
 * @param input_output_len the length of input and output
 */
flea_err_e THR_flea_cbc_mode__encrypt_data(
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u8_t           key_len,
  const flea_u8_t*       iv,
  flea_al_u8_t           iv_len,
  const flea_u8_t*       input,
  flea_u8_t*             output,
  flea_dtl_t             input_output_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Decrypt data in CBC mode without using a context object.
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input, but partial overlapping is not allowed
 * @param input_output_len the length of input and output
 */
flea_err_e THR_flea_cbc_mode__decrypt_data(
  flea_block_cipher_id_e id,
  const flea_u8_t*       key,
  flea_al_u8_t           key_len,
  const flea_u8_t*       iv,
  flea_al_u8_t           iv_len,
  const flea_u8_t*       input,
  flea_u8_t*             output,
  flea_dtl_t             input_output_len
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
