/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/hash.h"
#include "internal/common/hash/sha256.h"
#include "internal/common/hash/sha512.h"
#include "internal/common/hash/md5.h"
#include "internal/common/hash/sha1.h"
#include "internal/common/hash/davies_meyer_hash.h"
#include "flea/error_handling.h"
#include "flea/array_util.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "flea/byte_vec.h"
#include "flea/bin_utils.h"

#include <string.h>

struct struct_flea_hash_config_entry_t
{
  flea_u8_t                     count_format__u8;
  flea_al_u8_t                  block_length;
  flea_al_u8_t                  output_length;
  flea_al_u8_t                  hash_state_length;
  flea_hash_id_e                hash_id;
  flea_u8_t                     max_allowed_input_byte_len_exponent__u8;
  flea_hash_init_f              init_func;
  THR_flea_hash_compression_f   compression_func;
  flea_hash_encode_hash_state_f encode_state_func;
};

const flea_hash_config_entry_t flea_array_hash_configs[] = {
#ifdef FLEA_HAVE_DAVIES_MEYER_HASH
  {
    .hash_id = flea_davies_meyer_aes128,
    .count_format__u8  = 8 | 1,
    .block_length      = 16,
    .output_length     = 16,
    .hash_state_length = 16,
    .max_allowed_input_byte_len_exponent__u8 = 0,
    .init_func         = flea_hash_davies_meyer_aes128_init,
    .compression_func  = THR_flea_hash_davies_meyer_aes128_compression,
    .encode_state_func = NULL
  },
#endif /* ifdef FLEA_HAVE_DAVIES_MEYER_HASH */
#ifdef FLEA_HAVE_MD5
  {
    .hash_id = flea_md5,
    .count_format__u8  = 8 | 0,
    .block_length      = 64,
    .output_length     = 16,
    .hash_state_length = 16,
    .max_allowed_input_byte_len_exponent__u8 = 0,
    .init_func         = flea_md5_init,
    .compression_func  = THR_flea_md5_compression_function,
    .encode_state_func = flea_md5_encode_hash_state
  },
#endif /* ifdef FLEA_HAVE_MD5 */
#ifdef FLEA_HAVE_SHA1
  {
    .hash_id = flea_sha1,
    .count_format__u8  = 8 | 1,
    .block_length      = 64,
    .output_length     = 20,
    .hash_state_length = 20,
    .max_allowed_input_byte_len_exponent__u8 = 61,
    .init_func         = flea_sha1_init,
    .compression_func  = THR_flea_sha1_compression_function,
    .encode_state_func = flea_sha256_encode_hash_state
  },
#endif /* ifdef FLEA_HAVE_SHA1 */
#ifdef FLEA_HAVE_SHA224_256
  {
    .hash_id = flea_sha224,
    .count_format__u8  = 8 | 1,
    .block_length      = 64,
    .output_length     = 28,
    .hash_state_length = 32,
    .max_allowed_input_byte_len_exponent__u8 = 61,
    .init_func         = flea_sha224_init,
    .compression_func  = THR_flea_sha256_compression_function,
    .encode_state_func = flea_sha256_encode_hash_state
  },
  {
    .hash_id = flea_sha256,
    .count_format__u8  = 8 | 1,
    .block_length      = 64,
    .output_length     = 32,
    .hash_state_length = 32,
    .max_allowed_input_byte_len_exponent__u8 = 61,
    .init_func         = flea_sha256_init,
    .compression_func  = THR_flea_sha256_compression_function,
    .encode_state_func = flea_sha256_encode_hash_state
  },
#endif /* ifdef FLEA_HAVE_SHA224_256 */
#ifdef FLEA_HAVE_SHA384_512
  {
    .hash_id = flea_sha384,
    .count_format__u8  = 16 | 1,
    .block_length      = 128,
    .output_length     = 48,
    .hash_state_length = 64,
    .max_allowed_input_byte_len_exponent__u8 = 125,
    .init_func         = flea_sha384_init,
    .compression_func  = THR_flea_sha512_compression_function,
    .encode_state_func = flea_sha512_encode_hash_state
  },
  {
    .hash_id = flea_sha512,
    .count_format__u8  = 16 | 1,
    .block_length      = 128,
    .output_length     = 64,
    .hash_state_length = 64,
    .max_allowed_input_byte_len_exponent__u8 = 125,
    .init_func         = flea_sha512_init,
    .compression_func  = THR_flea_sha512_compression_function,
    .encode_state_func = flea_sha512_encode_hash_state
  }
#endif /* ifdef FLEA_HAVE_SHA384_512 */
};

static const flea_hash_config_entry_t* flea_hash__get_hash_config_by_id(flea_hash_id_e id)
{
  flea_al_u16_t i;

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(flea_array_hash_configs); i++)
  {
    if(id == flea_array_hash_configs[i].hash_id)
    {
      return &flea_array_hash_configs[i];
    }
  }
  return NULL;
}

flea_al_u8_t flea_hash__get_output_length_by_id(flea_hash_id_e id)
{
  const flea_hash_config_entry_t* config = flea_hash__get_hash_config_by_id(id);

  if(config == NULL)
  {
    return 0;
  }
  return config->output_length;
}

flea_err_e THR_flea_hash_ctx_t__ctor_copy(
  flea_hash_ctx_t*       p_ctx_new,
  const flea_hash_ctx_t* p_ctx
)
{
  FLEA_THR_BEG_FUNC();

  p_ctx_new->p_config = p_ctx->p_config;
  if(p_ctx_new->p_config == NULL)
  {
    FLEA_THROW("could not find hash id for merkle-damgard scheme", FLEA_ERR_INV_ALGORITHM);
  }
#ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM(p_ctx_new->pending_buffer, p_ctx_new->p_config->block_length);
  FLEA_ALLOC_MEM(p_ctx_new->hash_state, p_ctx_new->p_config->hash_state_length);
  // FLEA_ALLOC_MEM_ARR(p_ctx_new->counter__bu32, p_ctx_new->counter_block_arr_len__u8);
#endif
  memcpy(
    p_ctx_new->pending_buffer,
    p_ctx->pending_buffer,
    p_ctx_new->p_config->block_length * sizeof(p_ctx_new->pending_buffer[0])
  );
  memcpy(p_ctx_new->hash_state, p_ctx->hash_state, p_ctx_new->p_config->hash_state_length);
  FLEA_CCALL(THR_flea_len_ctr_t__ctor_copy(&p_ctx_new->len_ctr__t, &p_ctx->len_ctr__t));
  p_ctx_new->pending = p_ctx->pending;
  p_ctx_new->total_byte_length = p_ctx->total_byte_length;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_hash_ctx_t__ctor(
  flea_hash_ctx_t* p_ctx,
  flea_hash_id_e   id
)
{
  flea_al_u8_t counter_block_arr_len__u8;

  FLEA_THR_BEG_FUNC();

  p_ctx->p_config = flea_hash__get_hash_config_by_id(id);
  if(p_ctx->p_config == NULL)
  {
    FLEA_THROW("could not find hash id for merkle-damgard scheme", FLEA_ERR_INV_ALGORITHM);
  }
  counter_block_arr_len__u8 = (p_ctx->p_config->count_format__u8 & ~1) / sizeof(p_ctx->len_ctr__t.counter__bu32[0]);
  FLEA_CCALL(
    THR_flea_len_ctr_t__ctor(
      &p_ctx->len_ctr__t,
      counter_block_arr_len__u8,
      p_ctx->p_config->max_allowed_input_byte_len_exponent__u8,
      0
    )
  );
#ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM(p_ctx->pending_buffer, p_ctx->p_config->block_length);
  FLEA_ALLOC_MEM(p_ctx->hash_state, p_ctx->p_config->hash_state_length);
#endif
  flea_hash_ctx_t__reset(p_ctx);
  FLEA_THR_FIN_SEC_empty();
}

void flea_hash_ctx_t__reset(flea_hash_ctx_t* p_ctx)
{
  p_ctx->total_byte_length = 0;
  p_ctx->pending = 0;
  p_ctx->p_config->init_func(p_ctx);
  flea_len_ctr_t__reset(&p_ctx->len_ctr__t);
}

static flea_err_e THR_flea_hash_ctx_t__add_to_counter_block_and_check_limit(
  flea_hash_ctx_t* ctx__pt,
  flea_dtl_t       input_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_len_ctr_t__add_and_check_len_limit(&ctx__pt->len_ctr__t, input_len__dtl));
  FLEA_THR_FIN_SEC_empty();
}

static void flea_hash__encode_length_BE(
  const flea_hash_ctx_t* ctx__pt,
  flea_u8_t*             output__pu8
)
{
  flea_al_s8_t i;

  for(i = ctx__pt->len_ctr__t.counter_block_arr_len__u8 - 1; i >= 0; i--)
  {
    flea__encode_U32_BE(ctx__pt->len_ctr__t.counter__bu32[i], output__pu8);
    output__pu8 += 4;
  }
}

static void flea_hash__encode_length_LE(
  const flea_hash_ctx_t* ctx__pt,
  flea_u8_t*             output__pu8
)
{
  flea_al_u8_t i;

  for(i = 0; i < ctx__pt->len_ctr__t.counter_block_arr_len__u8; i++)
  {
    flea__encode_U32_LE(ctx__pt->len_ctr__t.counter__bu32[i], output__pu8);
    output__pu8 += 4;
  }
}

flea_err_e THR_flea_hash_ctx_t__update(
  flea_hash_ctx_t* p_ctx,
  const flea_u8_t* input,
  flea_dtl_t       input_len
)
{
  flea_al_u8_t block_length = p_ctx->p_config->block_length;
  flea_dtl_t nb_full_blocks, tail_len, i;
  THR_flea_hash_compression_f THR_compr_func = p_ctx->p_config->compression_func;

  FLEA_THR_BEG_FUNC();
  // first, complete the pending bytes
  FLEA_CCALL(THR_flea_hash_ctx_t__add_to_counter_block_and_check_limit(p_ctx, input_len));
  if(p_ctx->pending)
  {
    flea_al_u8_t left    = block_length - p_ctx->pending;
    flea_al_u8_t to_copy = FLEA_MIN(left, input_len);
    memcpy(p_ctx->pending_buffer + p_ctx->pending, input, to_copy);
    input_len      -= to_copy;
    input          += to_copy;
    p_ctx->pending += to_copy;
  }
  if(p_ctx->pending == block_length)
  {
    FLEA_CCALL(THR_compr_func(p_ctx, p_ctx->pending_buffer));
    p_ctx->pending = 0;
  }
  nb_full_blocks = input_len / block_length;
  tail_len       = input_len % block_length;

  for(i = 0; i < nb_full_blocks; i++)
  {
    FLEA_CCALL(THR_compr_func(p_ctx, input));
    input += block_length;
  }
  if(tail_len != 0)
  {
    memcpy(p_ctx->pending_buffer, input, tail_len);
    p_ctx->pending = tail_len;
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_hash_ctx_t__update */

flea_err_e THR_flea_hash_ctx_t__final_byte_vec(
  flea_hash_ctx_t* p_ctx,
  flea_byte_vec_t* result__pt
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_byte_vec_t__resize(result__pt, p_ctx->p_config->output_length));
  FLEA_CCALL(THR_flea_hash_ctx_t__final(p_ctx, result__pt->data__pu8));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_hash_ctx_t__final(
  flea_hash_ctx_t* p_ctx,
  flea_u8_t*       output
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__final_with_length_limit(p_ctx, output, p_ctx->p_config->output_length));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_hash_ctx_t__final_with_length_limit(
  flea_hash_ctx_t* p_ctx,
  flea_u8_t*       output,
  flea_al_u16_t    output_length
)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t block_length = p_ctx->p_config->block_length;

  output_length = FLEA_MIN(p_ctx->p_config->output_length, output_length);
  THR_flea_hash_compression_f THR_compr_func = p_ctx->p_config->compression_func;
  // pending is always at least 1 byte smaller than the block size

  // fill up the last bock with the padding
  flea_al_u8_t zeroes = block_length - p_ctx->pending - 1;
  p_ctx->pending_buffer[p_ctx->pending] = 0x80;
  p_ctx->pending++;

  if(zeroes < p_ctx->len_ctr__t.counter_block_arr_len__u8 * sizeof(p_ctx->len_ctr__t.counter__bu32[0]))
  {
    // the current block is too small to place the length
    // fill up the pending block with zeroes and process it
    memset(p_ctx->pending_buffer + p_ctx->pending, 0, zeroes);
    FLEA_CCALL(THR_compr_func(p_ctx, p_ctx->pending_buffer));
    zeroes = block_length - p_ctx->len_ctr__t.counter_block_arr_len__u8
      * sizeof(p_ctx->len_ctr__t.counter__bu32[0]);
    p_ctx->pending = 0;
  }
  else
  {
    // reserve the space for the length encoding
    zeroes -= p_ctx->len_ctr__t.counter_block_arr_len__u8 * sizeof(p_ctx->len_ctr__t.counter__bu32[0]);
  }
  memset(&p_ctx->pending_buffer[p_ctx->pending], 0, zeroes);
  p_ctx->pending += zeroes;
  // now place the length
  flea_len_ctr_t__counter_byte_lengt_to_bit_length(&p_ctx->len_ctr__t);
  if(p_ctx->p_config->count_format__u8 & 1)
  {
    flea_hash__encode_length_BE(p_ctx, &p_ctx->pending_buffer[p_ctx->pending]);
  }
  else
  {
    flea_hash__encode_length_LE(p_ctx, &p_ctx->pending_buffer[p_ctx->pending]);
  }


  // now compress the final block
  FLEA_CCALL(THR_compr_func(p_ctx, p_ctx->pending_buffer));
  if(p_ctx->p_config->encode_state_func != NULL)
  {
    p_ctx->p_config->encode_state_func(p_ctx, output, output_length);
  }
  else
  {
    memcpy(output, p_ctx->hash_state, output_length);
  }

  p_ctx->pending = 0;
  p_ctx->total_byte_length = 0;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_hash_ctx_t__final_with_length_limit */

void flea_hash_ctx_t__dtor(flea_hash_ctx_t* p_ctx)
{
  if(p_ctx->p_config == NULL)
  {
    return;
  }
  flea_len_ctr_t__dtor(&p_ctx->len_ctr__t);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(p_ctx->pending_buffer, p_ctx->p_config->block_length);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(p_ctx->hash_state, p_ctx->p_config->hash_state_length / sizeof(flea_u32_t));
}

flea_al_u16_t flea_hash_ctx_t__get_output_length(flea_hash_ctx_t* p_ctx)
{
  return p_ctx->p_config->output_length;
}

flea_hash_id_e flea_hash_ctx_t__get_hash_id(const flea_hash_ctx_t* p_ctx)
{
  return p_ctx->p_config->hash_id;
}

flea_err_e THR_flea_compute_hash_byte_vec(
  flea_hash_id_e   id,
  const flea_u8_t* input_pu8,
  flea_dtl_t       input_len_al_u16,
  flea_byte_vec_t* result__pt
)
{
  flea_hash_ctx_t ctx;
  flea_al_u16_t natural_output_len_al_u16;

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, id));
  natural_output_len_al_u16 = flea_hash_ctx_t__get_output_length(&ctx);
  FLEA_CCALL(THR_flea_byte_vec_t__resize(result__pt, natural_output_len_al_u16));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, input_pu8, input_len_al_u16));

  FLEA_CCALL(THR_flea_hash_ctx_t__final_byte_vec(&ctx, result__pt));

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx);
  );
}

flea_err_e THR_flea_compute_hash(
  flea_hash_id_e   id,
  const flea_u8_t* input_pu8,
  flea_dtl_t       input_len_al_u16,
  flea_u8_t*       output_pu8,
  flea_al_u16_t    output_len_al_u16
)
{
  flea_hash_ctx_t ctx;
  flea_al_u16_t natural_output_len_al_u16;

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, id));
  natural_output_len_al_u16 = flea_hash_ctx_t__get_output_length(&ctx);
  if(natural_output_len_al_u16 < output_len_al_u16)
  {
    FLEA_THROW(
      "desired output length of digest is longer than the hash functions natural output length",
      FLEA_ERR_INV_ARG
    );
  }
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, input_pu8, input_len_al_u16));

  FLEA_CCALL(THR_flea_hash_ctx_t__final_with_length_limit(&ctx, output_pu8, output_len_al_u16));

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx);
  );
}
