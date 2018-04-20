/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ae__H_
#define _flea_ae__H_

#include "internal/common/default.h"
#include "flea/block_cipher.h"
#include "flea/mac.h"
#include "internal/common/ae_int.h"
#include "internal/common/hash/ghash.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_AE

/**
 * Available Authenticate Encryption modes.
 */
typedef enum
{
# ifdef FLEA_HAVE_EAX
  flea_eax_aes128, flea_eax_aes192, flea_eax_aes256,
# endif
# ifdef FLEA_HAVE_GCM
  flea_gcm_aes128, flea_gcm_aes192, flea_gcm_aes256
# endif
} flea_ae_id_e;


/**
 * Authenticated Encryption context object.
 */
typedef struct
{
  flea_u8_t                     tag_len__u8;
  const flea_ae_config_entry_t* config__pt;
  flea_u8_t                     pending__u8;
# ifdef FLEA_HEAP_MODE
  flea_u8_t*                    buffer__bu8;
# else
  flea_u8_t                     buffer__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
# endif
  union
  {
# ifdef FLEA_HAVE_EAX
    flea_ae_eax_specific_t eax;
# endif
# ifdef FLEA_HAVE_GCM
    flea_ae_gcm_specific_t gcm;
# endif
  } mode_specific__u;
} flea_ae_ctx_t;

# define flea_ae_ctx_t__INIT_VALUE {.tag_len__u8 = 0}
# define flea_ae_ctx_t__INIT(__p) do {memset(__p, 0, sizeof(*(__p)));} while(0)

/**
 * Create an AE context. The context can be used for either encryption or
 * decryption by using the respective functions.
 *
 * @param ctx pointer to the context object to create
 * @param id the id of the AE scheme to use
 * @param key pointer to the key bytes
 * @param key_len number of key bytes
 * @param nonce pointer to the nonce bytes
 * @param nonce_len number of nonce bytes
 * @param header pointer to the header, i.e. associated data ( not part of the
 * ciphertext)
 * @param header_len length of the header in bytes
 * @param tag_len the desired length of the tag in bytes. May be smaller than
 * the chosen scheme's natural tag length. In that case, the scheme operates
 * with truncated tags
 *
 * @return flea error code
 * */
flea_err_e THR_flea_ae_ctx_t__ctor(
  flea_ae_ctx_t*   ctx,
  flea_ae_id_e     id,
  const flea_u8_t* key,
  flea_al_u16_t    key_len,
  const flea_u8_t* nonce,
  flea_al_u8_t     nonce_len,
  const flea_u8_t* header,
  flea_u16_t       header_len,
  flea_al_u8_t     tag_len
);


/**
 * Get the tag length of an AE ctx object.
 *
 * @param ctx pointer to the AE ctx object
 *
 * @return the byte length of the tags produced by this object
 */
flea_al_u8_t flea_ae_ctx_t__get_tag_length(flea_ae_ctx_t const* ctx);


/**
 * Destroy an AE context object.
 *
 * @param ctx pointer to the object to destroy
 */
void flea_ae_ctx_t__dtor(flea_ae_ctx_t* ctx);

/**
 * Feed a ctx with plaintext data and produce ciphertext output. The function
 * writes the same number of bytes of ciphertext as the plaintext input.
 *
 * @param ctx the AE context to use
 * @param input pointer to the plaintext bytes
 * @param output pointer to the location where the ciphertext shall be output
 * @param input_output_len length of input and output in bytes
 *
 * @return flea error code
 */
flea_err_e THR_flea_ae_ctx_t__update_encryption(
  flea_ae_ctx_t*   ctx,
  const flea_u8_t* input,
  flea_u8_t*       output,
  flea_dtl_t       input_output_len
);

/**
 * Finalize an AE encryption operation. The number of bytes written to tag is
 * equal to the length of tag_len in the call to THR_flea_ae_ctx_t__ctor
 *
 * @param[in,out] ctx the AE context to use
 * @param[out] tag memory location where to store the generated AE tag
 * @param[in,out] tag_len Must point to the size of the memory location at tag on input. Receives the actual tag length after the function return. If the length specified on input is smaller than the natural size of the MAC's tag, then the MAC is truncated.
 *
 * @return flea error code
 */
flea_err_e THR_flea_ae_ctx_t__final_encryption(
  flea_ae_ctx_t* ctx,
  flea_u8_t*     tag,
  flea_al_u8_t*  tag_len
);

/**
 * Feed an AE ctx with ciphertext data for decryption. The number of bytes
 * output may be smaller than the input length. This is due to the fact that the
 * last part of the input data is expected to be the AE tag. Accordingly, the
 * algorithm has to buffer the final block within each call to this function,
 * since that will be the tag if not more data follows.
 *
 * @param ctx the AE context to use
 * @param[in] input the ciphertext input data
 * @param[in] input_len length of the ciphertext input data
 * @param[out] output pointer to the memory location where to store the output
 * @param[in,out] output_len On input, this must hold the maximum length of the
 * memory location where to store the output. On function return, this receives
 * the number of actually written bytes to the output memory. output_len can be
 * smaller than input_len, but not larger. This behaviour is due to the
 * buffering of the last part of the input data as those may potential be
 * (partly) the tag.
 *
 * @return flea error code
 */
flea_err_e THR_flea_ae_ctx_t__update_decryption(
  flea_ae_ctx_t*   ctx,
  const flea_u8_t* input,
  flea_dtl_t       input_len,
  flea_u8_t*       output,
  flea_dtl_t*      output_len
);

/**
 * Finalize the decryption operation. All plaintext has already been output by
 * previous calls to THR_flea_ae_ctx_t__update_decryption. This function
 * generates the tag value based on the input data and verifies it against the
 * AE tag which was provided as the last part of the input data in the last call
 * to THR_flea_ae_ctx_t__update_decryption.
 *
 * @param ctx the AE context to use
 *
 * @return flea error code. If the MAC verification failed, FLEA_ERR_INV_MAC is
 * returned. if it succeeded, FLEA_ERR_FINE is returned.
 *
 */
flea_err_e THR_flea_ae_ctx_t__final_decryption(flea_ae_ctx_t* ctx);

/**
 * Encrypt a complete plaintext using an AE scheme.
 *
 * @param id the id of the AE scheme to use
 * @param key pointer to the key bytes
 * @param key_len number of key bytes
 * @param nonce pointer to the nonce bytes
 * @param nonce_len number of nonce bytes
 * @param header pointer to the header, i.e. associated data ( not part of the
 * ciphertext)
 * @param header_len length of the header in bytes
 * @param input the plaintext
 * @param output the ciphertext
 * @param input_output_len the length of input and output
 * @param tag pointer to the memory location where to write the AE tag
 * @param tag_len desired length of the tag
 *
 * @return flea error code
 */
flea_err_e THR_flea_ae__encrypt(
  flea_ae_id_e     id,
  const flea_u8_t* key,
  flea_dtl_t       key_len,
  const flea_u8_t* nonce,
  flea_dtl_t       nonce_len,
  const flea_u8_t* header,
  flea_dtl_t       header_len,
  const flea_u8_t* input,
  flea_u8_t*       output,
  flea_dtl_t       input_output_len,
  flea_u8_t*       tag,
  flea_al_u8_t     tag_len
);

/**
 * Decrypt a complete plaintext using an AE scheme.
 *
 * @param id the id of the AE scheme to use
 * @param key pointer to the key bytes
 * @param key_len number of key bytes
 * @param nonce pointer to the nonce bytes
 * @param nonce_len number of nonce bytes
 * @param header pointer to the header, i.e. associated data ( not part of the
 * ciphertext)
 * @param header_len length of the header in bytes
 * @param input the ciphertext
 * @param output the plaintext
 * @param input_output_len the length of input and output
 * @param tag pointer to the memory location where the tag is stored, e.g. at
 * the end of ciphertext.
 * @param tag_len length of the tag
 *
 * @return flea error code. If the MAC verification failed, FLEA_ERR_INV_MAC is
 * returned.
 */
flea_err_e THR_flea_ae__decrypt(
  flea_ae_id_e     id,
  const flea_u8_t* key,
  flea_dtl_t       key_len,
  const flea_u8_t* nonce,
  flea_dtl_t       nonce_len,
  const flea_u8_t* header,
  flea_dtl_t       header_len,
  const flea_u8_t* input,
  flea_u8_t*       output,
  flea_dtl_t       input_output_len,
  const flea_u8_t* tag,
  flea_al_u8_t     tag_len
);

#endif // ifdef FLEA_HAVE_AE

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
