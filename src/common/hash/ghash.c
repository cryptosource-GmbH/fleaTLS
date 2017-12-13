/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/ae.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include "flea/util.h"
#include "internal/common/hash/ghash.h"
#include "flea/error_handling.h"

#ifdef FLEA_HAVE_GCM

# define __FLEA_GHASH_STATE_U32_ARR_LEN (32 + 32 + 16 / 4 + 16 / 4)

static const flea_u16_t ghash_lo[16] = {
  0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/**
 * Lshift smaller than shiftwidth 32
 */
# define FLEA_LSHIFT_U64_AU32_SMALL(in, out, shift) \
  do { \
    out[1] = (in[1] << shift); \
    if(shift <= 32) {out[1] |= (in[0] >> (32 - shift));} \
    out[0] = in[0] << shift; \
  } while(0);

# define FLEA_RSHIFT_U64_AU32_SMALL(in, out, shift) \
  do { \
    out[0] = (in[0] >> shift); \
    if(shift <= 32) {out[0] |= (in[1] << (32 - shift));} \
    out[1] = in[1] >> shift; \
  } while(0);

/**
 * Lshift greater or equal than 32
 */
# define FLEA_LSHIFT_U64_AU32_LARGE(in, out, shift) \
  do { \
    out[1] = (in[0] << (32 - (64 - shift))); \
    out[0] = 0; \
  } while(0);

# define FLEA_U64_OR_AU32(au32_in_out, au32_in) \
  do { \
    au32_in_out[0] |= au32_in[0]; \
    au32_in_out[1] |= au32_in[1]; \
  } while(0)

static void ghash_process_block(
  flea_ghash_ctx_t* ctx__pt, /*const flea_u8_t x[__FLEA_GHASH_BLOCK_SIZE],*/
  flea_u8_t         output[__FLEA_GHASH_BLOCK_SIZE]
)
{
  int i;
  flea_u8_t lo, hi, rem;
  flea_u32_t zl_a[2];
  flea_u32_t zh_a[2];
  flea_u32_t tmp_a[2];
  flea_u8_t* x = output;

  lo      = (flea_u8_t) (x[15] & 0x0f);
  hi      = (flea_u8_t) (x[15] >> 4);
  zh_a[0] = ctx__pt->hh__bu32[2 * lo];
  zh_a[1] = ctx__pt->hh__bu32[2 * lo + 1];

  zl_a[0] = ctx__pt->hl__bu32[2 * lo];
  zl_a[1] = ctx__pt->hl__bu32[2 * lo + 1];

  for(i = 29; i >= -1; i--)
  {
    if(i & 1)
    {
      hi = (flea_u8_t) (x[(i + 1) / 2] >> 4);
    }
    else
    {
      hi = (flea_u8_t) (x[(i + 1) / 2] & 0x0f);
    }
    rem = (flea_u8_t) (zl_a[0] & 0x0f);

    FLEA_LSHIFT_U64_AU32_LARGE(zh_a, tmp_a, 60);
    FLEA_RSHIFT_U64_AU32_SMALL(zl_a, zl_a, 4);
    FLEA_U64_OR_AU32(zl_a, tmp_a);
    FLEA_RSHIFT_U64_AU32_SMALL(zh_a, zh_a, 4);

    tmp_a[0] = ghash_lo[rem];
    tmp_a[1] = 0;
    FLEA_LSHIFT_U64_AU32_LARGE(tmp_a, tmp_a, 48);
    zh_a[0] ^= tmp_a[0];
    zh_a[1] ^= tmp_a[1];


    zh_a[0] ^= ctx__pt->hh__bu32[2 * hi];
    zh_a[1] ^= ctx__pt->hh__bu32[2 * hi + 1];

    zl_a[0] ^= ctx__pt->hl__bu32[2 * hi];
    zl_a[1] ^= ctx__pt->hl__bu32[2 * hi + 1];
  }

# ifdef FLEA_HAVE_BE_ARCH_OPT
  FLEA_ENCODE_U32_BE(zh_a[1], output + 0);
  FLEA_ENCODE_U32_BE(zh_a[0], output + 4);
  FLEA_ENCODE_U32_BE(zl_a[1], output + 8);
  FLEA_ENCODE_U32_BE(zl_a[0], output + 12);
# else  /* ifdef FLEA_HAVE_BE_ARCH_OPT */
  flea__encode_U32_BE(zh_a[1], output + 0);
  flea__encode_U32_BE(zh_a[0], output + 4);
  flea__encode_U32_BE(zl_a[1], output + 8);
  flea__encode_U32_BE(zl_a[0], output + 12);
# endif /* ifdef FLEA_HAVE_BE_ARCH_OPT */
} /* ghash_process_block */

static void ghash_xor_and_process_block(
  flea_ghash_ctx_t* ctx__pt,
  flea_u8_t         output__pu8[__FLEA_GHASH_BLOCK_SIZE],
  const flea_u8_t*  input__pcu8,
  flea_al_u8_t      input_len__alu8
)
{
  flea__xor_bytes_in_place(output__pu8, input__pcu8, input_len__alu8);
  ghash_process_block(ctx__pt, output__pu8);
}

flea_err_t THR_flea_ghash_ctx_t__ctor(
  flea_ghash_ctx_t*          ctx__pt,
  const flea_ecb_mode_ctx_t* ecb_ctx__pt
)
{
  int i, j;
  flea_u32_t vl_a[2], vh_a[2];
  flea_u8_t h[__FLEA_GHASH_BLOCK_SIZE];

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(ctx__pt->hl__bu32, __FLEA_GHASH_STATE_U32_ARR_LEN);
  ctx__pt->hh__bu32      = ctx__pt->hl__bu32 + 32;
  ctx__pt->base_ctr__bu8 = (flea_u8_t*) (ctx__pt->hh__bu32 + 32);
  ctx__pt->state__bu8    = ctx__pt->base_ctr__bu8 + 16;
# endif /* ifdef FLEA_USE_HEAP_BUF */
  memset(h, 0, __FLEA_GHASH_BLOCK_SIZE);
  FLEA_CCALL(THR_flea_len_ctr_t__ctor(&ctx__pt->len_ctr__t, 2, 36, 32));
  FLEA_CCALL(THR_flea_ecb_mode_crypt_data(ecb_ctx__pt, h, h, ecb_ctx__pt->block_length__u8));

# ifdef FLEA_HAVE_BE_ARCH_OPT
  vh_a[1] = FLEA_DECODE_U32_BE(h + 0);
  vh_a[0] = FLEA_DECODE_U32_BE(h + 4);
  vl_a[1] = FLEA_DECODE_U32_BE(h + 8);
  vl_a[0] = FLEA_DECODE_U32_BE(h + 12);
# else  /* ifdef FLEA_HAVE_BE_ARCH_OPT */
  vh_a[1] = flea__decode_U32_BE(h);
  vh_a[0] = flea__decode_U32_BE(h + 4);
  vl_a[1] = flea__decode_U32_BE(h + 8);
  vl_a[0] = flea__decode_U32_BE(h + 12);
# endif /* ifdef FLEA_HAVE_BE_ARCH_OPT */

  ctx__pt->hl__bu32[16] = vl_a[0];
  ctx__pt->hl__bu32[17] = vl_a[1];

  ctx__pt->hh__bu32[16] = vh_a[0];
  ctx__pt->hh__bu32[17] = vh_a[1];

  ctx__pt->hh__bu32[0] = 0;
  ctx__pt->hh__bu32[1] = 0;

  ctx__pt->hl__bu32[0] = 0;
  ctx__pt->hl__bu32[1] = 0;

  for(i = 4; i > 0; i >>= 1)
  {
    flea_u32_t tmp_a[2];
    flea_u32_t T = (flea_u32_t) (vl_a[0] & 1) * 0xe1000000UL;
    FLEA_LSHIFT_U64_AU32_LARGE(vh_a, tmp_a, 63);
    FLEA_RSHIFT_U64_AU32_SMALL(vl_a, vl_a, 1);
    FLEA_U64_OR_AU32(vl_a, tmp_a);
    FLEA_RSHIFT_U64_AU32_SMALL(vh_a, vh_a, 1);
    vh_a[1] ^= T;

    ctx__pt->hl__bu32[2 * i]     = vl_a[0];
    ctx__pt->hl__bu32[2 * i + 1] = vl_a[1];

    ctx__pt->hh__bu32[2 * i]     = vh_a[0];
    ctx__pt->hh__bu32[2 * i + 1] = vh_a[1];
  }
  for(i = 2; i < 16; i <<= 1)
  {
    flea_u32_t* HiL_a = ctx__pt->hl__bu32 + 2 * i;
    flea_u32_t* HiH_a = ctx__pt->hh__bu32 + 2 * i;

    vh_a[0] = HiH_a[0];
    vh_a[1] = HiH_a[1];

    vl_a[0] = HiL_a[0];
    vl_a[1] = HiL_a[1];

    for(j = 1; j < i; j++)
    {
      HiH_a[2 * j]     = vh_a[0] ^ ctx__pt->hh__bu32[2 * j];
      HiH_a[2 * j + 1] = vh_a[1] ^ ctx__pt->hh__bu32[2 * j + 1];

      HiL_a[2 * j]     = vl_a[0] ^ ctx__pt->hl__bu32[2 * j];
      HiL_a[2 * j + 1] = vl_a[1] ^ ctx__pt->hl__bu32[2 * j + 1];
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ghash_ctx_t__ctor */

flea_err_t THR_flea_ghash_ctx_t__start(
  flea_ghash_ctx_t*          ctx,
  const flea_ecb_mode_ctx_t* ecb_ctx__pt,
  const flea_u8_t*           iv,
  size_t                     iv_len,
  const flea_u8_t*           add,
  flea_al_u16_t              hdr_len__u16,
  flea_u8_t*                 ctr_block__pu8
)
{
  FLEA_DECL_BUF(work__bu8, flea_u8_t, 32);
  const flea_u8_t* p;
  size_t use_len;

  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(work__bu8, __FLEA_GHASH_BLOCK_SIZE);
  memset(ctr_block__pu8, 0, __FLEA_GHASH_BLOCK_SIZE);
  memset(ctx->state__bu8, 0, __FLEA_GHASH_BLOCK_SIZE);
  ctx->hdr_len__u16       = 0;
  ctx->pend_input_len__u8 = 0;

  if(iv_len == 12)
  {
    memcpy(ctr_block__pu8, iv, iv_len);
    ctr_block__pu8[15] = 1;
  }
  else
  {
    memset(work__bu8, 0, __FLEA_GHASH_BLOCK_SIZE);
    FLEA_ENCODE_U32_BE(iv_len * 8, work__bu8 + 12);

    p = iv;
    while(iv_len > 0)
    {
      use_len = (iv_len < __FLEA_GHASH_BLOCK_SIZE) ? iv_len : __FLEA_GHASH_BLOCK_SIZE;
      ghash_xor_and_process_block(ctx, ctr_block__pu8, p, use_len);
      iv_len -= use_len;
      p      += use_len;
    }
    ghash_xor_and_process_block(ctx, ctr_block__pu8, work__bu8, __FLEA_GHASH_BLOCK_SIZE);
  }
  FLEA_CCALL(
    THR_flea_ecb_mode_crypt_data(
      ecb_ctx__pt,
      ctr_block__pu8,
      ctx->base_ctr__bu8,
      ecb_ctx__pt->block_length__u8
    )
  );

  ctx->hdr_len__u16 = hdr_len__u16;
  p = add;
  while(hdr_len__u16 > 0)
  {
    use_len = (hdr_len__u16 < __FLEA_GHASH_BLOCK_SIZE) ? hdr_len__u16 : __FLEA_GHASH_BLOCK_SIZE;
    ghash_xor_and_process_block(ctx, ctx->state__bu8, p, use_len);
    hdr_len__u16 -= use_len;
    p += use_len;
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF(work__bu8);
  );
} /* THR_flea_ghash_ctx_t__start */

flea_err_t THR_flea_ghash_ctx_t__update(
  flea_ghash_ctx_t* ctx__pt,
  flea_dtl_t        input_len__dtl,
  const flea_u8_t*  input__pcu8
)
{
  flea_al_u8_t left__alu8, to_copy__alu8, tail_len__alu8;
  flea_dtl_t nb_full_blocks__alu16, i;
  flea_al_u8_t pend_len__alu8 = ctx__pt->pend_input_len__u8;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_len_ctr_t__add_and_check_len_limit(&ctx__pt->len_ctr__t, input_len__dtl));
  left__alu8    = __FLEA_GHASH_BLOCK_SIZE - pend_len__alu8;
  to_copy__alu8 = FLEA_MIN(input_len__dtl, left__alu8);
  flea__xor_bytes_in_place(ctx__pt->state__bu8 + pend_len__alu8, input__pcu8, to_copy__alu8);
  input__pcu8    += to_copy__alu8;
  input_len__dtl -= to_copy__alu8;
  pend_len__alu8 += to_copy__alu8;

  nb_full_blocks__alu16 = input_len__dtl / __FLEA_GHASH_BLOCK_SIZE;
  tail_len__alu8        = input_len__dtl % __FLEA_GHASH_BLOCK_SIZE;
  if(pend_len__alu8 == __FLEA_GHASH_BLOCK_SIZE)
  {
    ghash_process_block(ctx__pt, ctx__pt->state__bu8);
    pend_len__alu8 = 0;
  }
  for(i = 0; i < nb_full_blocks__alu16; i++)
  {
    ghash_xor_and_process_block(ctx__pt, ctx__pt->state__bu8, input__pcu8, __FLEA_GHASH_BLOCK_SIZE);
    input__pcu8 += __FLEA_GHASH_BLOCK_SIZE;
  }
  if(tail_len__alu8 != 0)
  {
    flea__xor_bytes_in_place(ctx__pt->state__bu8, input__pcu8, tail_len__alu8);
    pend_len__alu8 = tail_len__alu8;
  }
  ctx__pt->pend_input_len__u8 = pend_len__alu8;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ghash_ctx_t__update */

void flea_ghash_ctx_t__finish(
  flea_ghash_ctx_t* ctx__pt,
  flea_u8_t*        tag,
  size_t            tag_len
)
{
  flea_u8_t* work_buf = ctx__pt->base_ctr__bu8;
  flea_u32_t orig_add_len__u32 = ctx__pt->hdr_len__u16 * 8;

  flea_len_ctr_t__counter_byte_lengt_to_bit_length(&ctx__pt->len_ctr__t);
  if(ctx__pt->pend_input_len__u8)
  {
    ghash_process_block(ctx__pt, ctx__pt->state__bu8);
  }
  if(tag_len != 0) memcpy(tag, ctx__pt->base_ctr__bu8, tag_len);

  if(ctx__pt->len_ctr__t.counter__bu32[0] || ctx__pt->len_ctr__t.counter__bu32[1] || orig_add_len__u32)
  {
    memset(work_buf, 0, __FLEA_GHASH_BLOCK_SIZE);
# ifdef FLEA_HAVE_BE_ARCH_OPT
    FLEA_ENCODE_U32_BE(0, work_buf);
    FLEA_ENCODE_U32_BE(orig_add_len__u32, work_buf + 4);
    FLEA_ENCODE_U32_BE(ctx__pt->len_ctr__t.counter__bu32[1], work_buf + 8);
    FLEA_ENCODE_U32_BE(ctx__pt->len_ctr__t.counter__bu32[0], work_buf + 12);
# else  /* ifdef FLEA_HAVE_BE_ARCH_OPT */
    flea__encode_U32_BE(0, work_buf);
    flea__encode_U32_BE(orig_add_len__u32, work_buf + 4);
    flea__encode_U32_BE(ctx__pt->len_ctr__t.counter__bu32[1], work_buf + 8);
    flea__encode_U32_BE(ctx__pt->len_ctr__t.counter__bu32[0], work_buf + 12);
# endif /* ifdef FLEA_HAVE_BE_ARCH_OPT */

    ghash_xor_and_process_block(ctx__pt, ctx__pt->state__bu8, work_buf, __FLEA_GHASH_BLOCK_SIZE);
    flea__xor_bytes_in_place(tag, ctx__pt->state__bu8, tag_len);
  }
}

void flea_ghash_ctx_t__dtor(flea_ghash_ctx_t* ctx__pt)
{
  flea_len_ctr_t__dtor(&ctx__pt->len_ctr__t);
# ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(ctx__pt->hl__bu32, __FLEA_GHASH_STATE_U32_ARR_LEN);
# endif
}

#endif /* ifdef FLEA_HAVE_GCM */
