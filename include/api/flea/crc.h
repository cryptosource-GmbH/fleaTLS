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
#ifndef _flea_crc__H_
#define _flea_crc__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Compute the CRC16 (CCIT) checksum of the given data.
 *
 * @param crc_init CRC start value (normally = 0, or an intermediate CRC16
 * result)
 * @param data pointer to the data to compute the checksum of
 * @param data_len length of data
 */
flea_u16_t flea_crc16_ccit_compute(
  flea_u16_t       crc_init,
  const flea_u8_t* data,
  flea_dtl_t       data_len
);

/**
 * Compute the CRC32 checksum of the given data.
 *
 * @param crc_init CRC start value (normally = 0, or an intermediate CRC32
 * result)
 * @param data pointer to the data to compute the checksum of
 * @param data_len length of data
 */
flea_u32_t flea_crc32_compute(
  flea_u32_t       crc_init,
  const flea_u8_t* data,
  flea_dtl_t       data_len
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
