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

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/block_cipher/aes.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"

#ifdef FLEA_USE_SMALL_AES


# define Nb 4


static const flea_u8_t flea_aes_sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

# ifdef FLEA_HAVE_AES_BLOCK_DECR
static const flea_u8_t flea_aes_rsbox[256] =
{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
# endif // #ifdef FLEA_HAVE_AES_BLOCK_DECR


static const flea_u8_t Rcon[] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

flea_err_e THR_flea_aes_setup_encr_key(
  flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*     key__pcu8
)
{
  flea_aes_setup_encr_key(ctx__pt, key__pcu8);
  return FLEA_ERR_FINE;
}

void flea_aes_setup_encr_key(
  flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*     key__pcu8
)
{
  flea_u32_t i, j, k;
  flea_u8_t tempa[4];
  flea_al_u16_t keyBits = 8 * ctx__pt->key_byte_size__u8;

  flea_al_u8_t Nr, Nk;
  flea_u8_t* expanded_key__pu8 = (flea_u8_t*) ctx__pt->expanded_key__bu8;

  if(keyBits == 128)
  {
    Nr = 10;
    Nk = 4;
  }
  else if(keyBits == 192)
  {
    Nr = 12;
    Nk = 6;
  }
  else
  {
    Nr = 14;
    Nk = 8;
  }
  ctx__pt->nb_rounds__u8 = Nr;
  for(i = 0; i < Nk; ++i)
  {
    expanded_key__pu8[(i * 4) + 0] = key__pcu8[(i * 4) + 0];
    expanded_key__pu8[(i * 4) + 1] = key__pcu8[(i * 4) + 1];
    expanded_key__pu8[(i * 4) + 2] = key__pcu8[(i * 4) + 2];
    expanded_key__pu8[(i * 4) + 3] = key__pcu8[(i * 4) + 3];
  }
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j] = expanded_key__pu8[(i - 1) * 4 + j];
    }
    if(i % Nk == 0)
    {
      k        = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = k;

      tempa[0] = flea_aes_sbox[tempa[0]];
      tempa[1] = flea_aes_sbox[tempa[1]];
      tempa[2] = flea_aes_sbox[tempa[2]];
      tempa[3] = flea_aes_sbox[tempa[3]];

      tempa[0] = tempa[0] ^ Rcon[i / Nk - 1];
    }
    else if(Nk > 6 && i % Nk == 4)
    {
      {
        tempa[0] = flea_aes_sbox[tempa[0]];
        tempa[1] = flea_aes_sbox[tempa[1]];
        tempa[2] = flea_aes_sbox[tempa[2]];
        tempa[3] = flea_aes_sbox[tempa[3]];
      }
    }
    expanded_key__pu8[i * 4 + 0] = expanded_key__pu8[(i - Nk) * 4 + 0] ^ tempa[0];
    expanded_key__pu8[i * 4 + 1] = expanded_key__pu8[(i - Nk) * 4 + 1] ^ tempa[1];
    expanded_key__pu8[i * 4 + 2] = expanded_key__pu8[(i - Nk) * 4 + 2] ^ tempa[2];
    expanded_key__pu8[i * 4 + 3] = expanded_key__pu8[(i - Nk) * 4 + 3] ^ tempa[3];
  }
} /* flea_aes_setup_encr_key */

# ifdef FLEA_HAVE_AES_BLOCK_DECR
flea_err_e THR_flea_aes_setup_decr_key(
  flea_ecb_mode_ctx_t* ctx__p_t,
  const flea_u8_t*     cipherKey
)
{
  return THR_flea_aes_setup_encr_key(ctx__p_t, cipherKey);
}

# endif // #ifdef FLEA_HAVE_AES_BLOCK_DECR

static void flea_aes_small_add_round_key(
  flea_u8_t        round,
  flea_u8_t*       state__pu8,
  const flea_u8_t* round_key__pcu8
)
{
  flea_al_u8_t i;

  for(i = 0; i < 16; ++i)
  {
    state__pu8[i] ^= round_key__pcu8[round * Nb * 4 + i];
  }
}

static void flea_aes_small_subbytes(flea_u8_t* state__pu8)
{
  flea_u8_t i;

  for(i = 0; i < 16; ++i)
  {
    state__pu8[i] = flea_aes_sbox[state__pu8[i]];
  }
}

static void flea_aes_small_shift_rows(flea_u8_t* state__pu8)
{
  flea_u8_t temp;

  // Rotate first row 1 columns to left
  temp = state__pu8[0 * 4 + 1];
  state__pu8[0 * 4 + 1] = state__pu8[1 * 4 + 1];
  state__pu8[1 * 4 + 1] = state__pu8[2 * 4 + 1];
  state__pu8[2 * 4 + 1] = state__pu8[3 * 4 + 1];
  state__pu8[3 * 4 + 1] = temp;

  // Rotate second row 2 columns to left
  temp = state__pu8[0 * 4 + 2];
  state__pu8[0 * 4 + 2] = state__pu8[2 * 4 + 2];
  state__pu8[2 * 4 + 2] = temp;

  temp = state__pu8[1 * 4 + 2];
  state__pu8[1 * 4 + 2] = state__pu8[3 * 4 + 2];
  state__pu8[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to left
  temp = state__pu8[0 * 4 + 3];
  state__pu8[0 * 4 + 3] = state__pu8[3 * 4 + 3];
  state__pu8[3 * 4 + 3] = state__pu8[2 * 4 + 3];
  state__pu8[2 * 4 + 3] = state__pu8[1 * 4 + 3];
  state__pu8[1 * 4 + 3] = temp;
}

static flea_u8_t xtime(flea_u8_t x)
{
  return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static void flea_aes_small_mix_col(flea_u8_t* state__pu8)
{
  flea_u8_t i;
  flea_u8_t Tmp, Tm, t;

  for(i = 0; i < 4; ++i)
  {
    t   = state__pu8[i * 4 + 0];
    Tmp = state__pu8[i * 4 + 0] ^ state__pu8[i * 4 + 1] ^ state__pu8[i * 4 + 2] ^ state__pu8[i * 4 + 3];
    Tm  = state__pu8[i * 4 + 0] ^ state__pu8[i * 4 + 1];
    Tm  = xtime(Tm);
    state__pu8[i * 4 + 0] ^= Tm ^ Tmp;
    Tm = state__pu8[i * 4 + 1] ^ state__pu8[i * 4 + 2];
    Tm = xtime(Tm);
    state__pu8[i * 4 + 1] ^= Tm ^ Tmp;
    Tm = state__pu8[i * 4 + 2] ^ state__pu8[i * 4 + 3];
    Tm = xtime(Tm);
    state__pu8[i * 4 + 2] ^= Tm ^ Tmp;
    Tm = state__pu8[i * 4 + 3] ^ t;
    Tm = xtime(Tm);
    state__pu8[i * 4 + 3] ^= Tm ^ Tmp;
  }
}

# ifdef FLEA_HAVE_AES_BLOCK_DECR
static flea_u8_t flea_small_aes_multiply(
  flea_u8_t x,
  flea_u8_t y
)
{
  flea_u8_t x_arr[4];
  flea_u8_t x_run = x;
  flea_al_u8_t i;

  for(i = 0; i < 4; i++)
  {
    x_run    = ((x_run << 1) ^ (((x_run >> 7) & 1) * 0x1b));
    x_arr[i] = x_run;
  }
  return ((y & 1) * x)
         ^ ((y >> 1 & 1) * x_arr[0])
         ^ ((y >> 2 & 1) * x_arr[1])
         ^ ((y >> 3 & 1) * x_arr[2])
         ^ ((y >> 4 & 1) * x_arr[3]);
}

static void flea_aes_small_inv_mix_col(flea_u8_t* state__pu8)
{
  flea_al_u8_t i, j;
  flea_u8_t a, b, c, d;

  for(i = 0; i < 4; ++i)
  {
    flea_u8_t vals__au8[4] = {0x0e, 0x09, 0x0d, 0x0b};
    a = (state__pu8)[i * 4 + 0];
    b = (state__pu8)[i * 4 + 1];
    c = (state__pu8)[i * 4 + 2];
    d = (state__pu8)[i * 4 + 3];

    for(j = 0; j < 4; j++)
    {
      state__pu8[i * 4
      + j] =
        flea_small_aes_multiply(
        a,
        vals__au8[j]
        )
        ^ flea_small_aes_multiply(
        b,
        vals__au8[(j + 3) % 4]
        ) ^ flea_small_aes_multiply(c, vals__au8[(j + 2) % 4]) ^ flea_small_aes_multiply(
        d,
        vals__au8[(j + 1) % 4]
        );
    }
  }
}

static void flea_aes_small_inv_subbytes(flea_u8_t* state__pu8)
{
  flea_u8_t i;

  for(i = 0; i < 16; ++i)
  {
    state__pu8[i] = flea_aes_rsbox[state__pu8[i]];
  }
}

static void flea_aes_small_inv_shift_rows(flea_u8_t* state__pu8)
{
  flea_u8_t temp;

  temp = state__pu8[3 * 4 + 1];
  state__pu8[3 * 4 + 1] = state__pu8[2 * 4 + 1];
  state__pu8[2 * 4 + 1] = state__pu8[1 * 4 + 1];
  state__pu8[1 * 4 + 1] = state__pu8[0 * 4 + 1];
  state__pu8[0 * 4 + 1] = temp;

  temp = state__pu8[0 * 4 + 2];
  state__pu8[0 * 4 + 2] = state__pu8[2 * 4 + 2];
  state__pu8[2 * 4 + 2] = temp;

  temp = state__pu8[1 * 4 + 2];
  state__pu8[1 * 4 + 2] = state__pu8[3 * 4 + 2];
  state__pu8[3 * 4 + 2] = temp;

  temp = state__pu8[0 * 4 + 3];
  state__pu8[0 * 4 + 3] = state__pu8[1 * 4 + 3];
  state__pu8[1 * 4 + 3] = state__pu8[2 * 4 + 3];
  state__pu8[2 * 4 + 3] = state__pu8[3 * 4 + 3];
  state__pu8[3 * 4 + 3] = temp;
}

# endif // #ifdef FLEA_HAVE_AES_BLOCK_DECR


void flea_aes_encrypt_block(
  const flea_ecb_mode_ctx_t* p_ctx,
  const flea_u8_t*           pt,
  flea_u8_t*                 ct
)
{
  flea_u8_t round       = 0;
  flea_u8_t* state__pu8 = ct;

  if(state__pu8 != pt)
  {
    memcpy(state__pu8, pt, 16);
  }
  flea_al_u8_t Nr = p_ctx->nb_rounds__u8;
  flea_aes_small_add_round_key(0, state__pu8, (flea_u8_t*) p_ctx->expanded_key__bu8);

  for(round = 1; round < Nr; ++round)
  {
    flea_aes_small_subbytes(state__pu8);
    flea_aes_small_shift_rows(state__pu8);
    flea_aes_small_mix_col(state__pu8);
    flea_aes_small_add_round_key(round, state__pu8, (flea_u8_t*) p_ctx->expanded_key__bu8);
  }

  flea_aes_small_subbytes(state__pu8);
  flea_aes_small_shift_rows(state__pu8);
  flea_aes_small_add_round_key(Nr, state__pu8, (flea_u8_t*) p_ctx->expanded_key__bu8);
}

# ifdef FLEA_HAVE_AES_BLOCK_DECR
void flea_aes_decrypt_block(
  const flea_ecb_mode_ctx_t* p_ctx,
  const flea_u8_t*           ct,
  flea_u8_t*                 pt
)
{
  flea_u8_t round       = 0;
  flea_al_u8_t Nr       = p_ctx->nb_rounds__u8;
  flea_u8_t* state__pu8 = pt;

  if(state__pu8 != ct)
  {
    memcpy(state__pu8, ct, 16);
  }
  flea_aes_small_add_round_key(Nr, state__pu8, (flea_u8_t*) p_ctx->expanded_key__bu8);

  for(round = Nr - 1; round > 0; round--)
  {
    flea_aes_small_inv_shift_rows(state__pu8);
    flea_aes_small_inv_subbytes(state__pu8);
    flea_aes_small_add_round_key(round, state__pu8, (flea_u8_t*) p_ctx->expanded_key__bu8);
    flea_aes_small_inv_mix_col(state__pu8);
  }

  flea_aes_small_inv_shift_rows(state__pu8);
  flea_aes_small_inv_subbytes(state__pu8);
  flea_aes_small_add_round_key(0, state__pu8, (flea_u8_t*) p_ctx->expanded_key__bu8);
}

# endif // #ifdef FLEA_HAVE_AES_BLOCK_DECR

#endif // #ifdef FLEA_USE_SMALL_AES
