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

#include "internal/common/enc_ecdsa_sig.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"

static flea_al_u8_t flea_determine_asn1_enc_short_int_content_len(
  const flea_u8_t* enc_int__pcu8,
  flea_al_u8_t     enc_int_len__alu8
)
{
  flea_al_u8_t i = 0;
  flea_al_u8_t result__alu8;

  while(i + 1 < enc_int_len__alu8 && enc_int__pcu8[i] == 0)
  {
    i++;
  }
  result__alu8 = enc_int_len__alu8 - i;
  if(enc_int__pcu8[i] & 0x80)
  {
    result__alu8++;
  }
  return result__alu8;
}

static flea_err_e THR_flea_encode_short_int_asn1(
  const flea_u8_t* enc_int__pcu8,
  flea_al_u8_t     enc_int_len__alu8,
  flea_byte_vec_t* result__pt
)
{
  flea_al_u8_t asn1_len__alu8 = 0;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_byte_vec_t__push_back(result__pt, FLEA_ASN1_INT));
  asn1_len__alu8 = flea_determine_asn1_enc_short_int_content_len(enc_int__pcu8, enc_int_len__alu8);
  FLEA_CCALL(THR_flea_byte_vec_t__push_back(result__pt, asn1_len__alu8));
  if(asn1_len__alu8 > enc_int_len__alu8)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__push_back(result__pt, 0x00));
    asn1_len__alu8--;
  }
  FLEA_CCALL(
    THR_flea_byte_vec_t__append(
      result__pt,
      &enc_int__pcu8[enc_int_len__alu8 - asn1_len__alu8],
      asn1_len__alu8
    )
  );


  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_asn1_encode_ecdsa_sig(
  const flea_u8_t* r__pcu8,
  flea_al_u8_t     r_len__alu8,
  const flea_u8_t* s__pcu8,
  flea_al_u8_t     s_len__alu8,
  flea_byte_vec_t* result__pt
)
{
  flea_al_u8_t r_asn1_len__alu8, s_asn1_len__alu8; /* both at max 65 for 521 bit curve */
  flea_al_u8_t seq_cont_len__alu8;

  FLEA_THR_BEG_FUNC();
  r_asn1_len__alu8   = flea_determine_asn1_enc_short_int_content_len(r__pcu8, r_len__alu8);
  s_asn1_len__alu8   = flea_determine_asn1_enc_short_int_content_len(s__pcu8, s_len__alu8);
  seq_cont_len__alu8 = r_asn1_len__alu8 + s_asn1_len__alu8 + 4;
  FLEA_CCALL(THR_flea_byte_vec_t__push_back(result__pt, FLEA_ASN1_SEQUENCE_CONSTRUCTED));
  if(seq_cont_len__alu8 > 127)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__push_back(result__pt, 0x81));
  }
  FLEA_CCALL(THR_flea_byte_vec_t__push_back(result__pt, seq_cont_len__alu8));
  FLEA_CCALL(THR_flea_encode_short_int_asn1(r__pcu8, r_len__alu8, result__pt));
  FLEA_CCALL(THR_flea_encode_short_int_asn1(s__pcu8, s_len__alu8, result__pt));

  FLEA_THR_FIN_SEC_empty();
}
