/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#ifndef _flea_fortuna__H_
# define _flea_fortuna__H_

# include "flea/types.h"
# include "internal/common/block_cipher/aes.h"
# include "flea/hash.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * AES-based CTR mode PRNG. Produces output as the CTR-mode key stream using
 * AES-256.
 */
typedef struct
{
  flea_u8_t           pending_output_len__u8;
# ifdef FLEA_HEAP_MODE
  flea_u8_t*          pending_output__bu8;
  flea_u8_t*          count_block__bu8;
  flea_u8_t*          key__bu8;
  flea_u8_t*          accu__bu8;
# else // ifdef FLEA_HEAP_MODE
  flea_u8_t           pending_output__bu8[FLEA_AES_BLOCK_LENGTH];
  flea_u8_t           count_block__bu8[FLEA_AES_BLOCK_LENGTH];
  flea_u8_t           key__bu8[FLEA_AES256_KEY_BYTE_LENGTH];
# endif // ifdef FLEA_HEAP_MODE
  flea_ecb_mode_ctx_t cipher_ctx__t;
} flea_ctr_mode_prng_t;


# ifdef FLEA_HEAP_MODE
#  define flea_ctr_mode_prng_t__INIT(__p) \
  do { \
    flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t); \
  } while(0)
# else // ifdef FLEA_HEAP_MODE
#  define flea_ctr_mode_prng_t__INIT(__p) \
  do { \
    flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t); \
  } while(0)
# endif // ifdef FLEA_HEAP_MODE

/**
 * Create a PRNG object.
 *
 * @param ctx__pt pointer to the object to create.
 * @param state__pcu8 initial seed value used to seed the PRNG. Will be hashed
 * by the PRNG to form its AES key.
 * @param state_len__alu8 the length of the seed
 *
 * @return error code
 */
flea_err_e THR_flea_ctr_mode_prng_t__ctor(
  flea_ctr_mode_prng_t* ctx__pt,
  const flea_u8_t*      state__pcu8,
  flea_al_u8_t          state_len__alu8
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Randomize a buffer without flushing the PRNG. 'Flushing' means to apply a
 * further cryptographic operation to its internal state that makes it impossible
 * to reconstruct previously generated output, i.e. achieve forward security.
 * This can be omitted for purposes of improved performance within a series
 * of output generation but flea_ctr_mode_prng_t__flush() should then be
 * called at the end of that series.
 *
 * @param ctx__pt pointer to the PRNG context object
 * @param mem__pu8 pointer to the memory area to randomize
 * @param mem_len__dtl length of the memory area
 *
 */
void flea_ctr_mode_prng_t__rndmz_no_flush(
  flea_ctr_mode_prng_t* ctx__pt,
  flea_u8_t*            mem__pu8,
  flea_dtl_t            mem_len__dtl
);

/**
 * Randomize a buffer and subsequently flushing the PRNG. 'Flushing' means to apply a
 * further cryptographic operation to its internal state that makes it impossible
 * to reconstruct previously generated output, i.e. achieve forward security.
 *
 * @param ctx__pt pointer to the PRNG context object
 * @param mem__pu8 pointer to the memory area to randomize
 * @param mem_len__dtl length of the memory area
 *
 */
void flea_ctr_mode_prng_t__rndmz(
  flea_ctr_mode_prng_t* ctx__pt,
  flea_u8_t*            mem__pu8,
  flea_dtl_t            mem_len__dtl
);

/**
 * Add additional seed data to the PRNG. Calling this function does never reduce the entropy level of the PRNG.
 *
 * @param ctx__pt pointer to the PRNG context object
 * @param seed__pcu8 pointer to the seed data
 * @param seed_len__dtl length of the seed data
 *
 * @return flea error code
 */
flea_err_e THR_flea_ctr_mode_prng_t__reseed(
  flea_ctr_mode_prng_t* ctx__pt,
  const flea_u8_t*      seed__pcu8,
  flea_dtl_t            seed_len__dtl
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Flush the internal state of the PRNG. After this operation, even when the
 * internal state of the PRNG would become public, reconstruction of previous
 * output is not possible.
 *
 * @param ctx__pt pointer to the PRNG context object
 */
void flea_ctr_mode_prng_t__flush(flea_ctr_mode_prng_t* ctx__pt);

/**
 * Destroy a PRNG object.
 *
 * @param ctx__pt pointer to the PRNG context object
 */
void flea_ctr_mode_prng_t__dtor(flea_ctr_mode_prng_t* ctx__pt);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
