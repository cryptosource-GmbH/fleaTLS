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
#include "flea/crc.h"

// computes ~crc16
// initial init value shall be zero for CCIT compatibility
flea_u16_t flea_crc16_ccit_compute(
  flea_u16_t       crc_init__u16,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  flea_dtl_t i;

  for(i = 0; i < data_len__dtl; i++)
  {
    flea_al_s8_t j;
    flea_u8_t byte = data__pcu8[i];

    crc_init__u16 ^= (byte << 8);
    for(j = 0; j < 8; j++)
    {
      flea_u16_t mask__u16 = -(((crc_init__u16) & (1 << 15)) >> 15);
      crc_init__u16 = (crc_init__u16 << 1) ^ (0x1021 & mask__u16);
      byte <<= 1;
    }
  }
  return crc_init__u16;
}

flea_u32_t flea_crc32_compute(
  flea_u32_t       crc_init__u32,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  flea_dtl_t i;
  flea_al_s8_t j;
  flea_u32_t byte, crc, mask;

  i   = 0;
  crc = ~crc_init__u32;
  for(i = 0; i < data_len__dtl; i++)
  {
    byte = data__pcu8[i];
    crc  = crc ^ byte;
    for(j = 7; j >= 0; j--)
    {
      mask = -(crc & 1);
      crc  = (crc >> 1) ^ (0xEDB88320 & mask);
    }
  }
  return ~crc;
}
