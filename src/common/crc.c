/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/types.h"

// computes ~crc16
// initial remainder shall be zero for CCIT compatibility
flea_u16_t flea_crc16_ccit_compute(flea_u16_t crc_init__u16, const flea_u8_t *data__pcu8, flea_dtl_t data_len__dtl)
{
  flea_dtl_t i;

  for(i = 0; i < data_len__dtl; i++)
  {
    flea_al_s8_t j;
    flea_u8_t byte = data__pcu8[i];

    crc_init__u16 ^= (byte << 8);
    for(j = 0; j < 8; j++)
    {
      flea_u16_t mask__u16 = -(((crc_init__u16 ) & (1 << 15)) >> 15);
      crc_init__u16 = (crc_init__u16 << 1) ^ (0x1021 & mask__u16);
      byte <<= 1;
    }
  }
  return crc_init__u16;
}
