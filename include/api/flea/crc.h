/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */
#ifndef _flea_crc__H_
#define _flea_crc__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Compute the CRC16 (CCIT) checksum of the given data.
 *
 * @param crc_init CRC start value
 * @param data pointer to the data to compute the checksum of
 * @param data_len length of data
 */
flea_u16_t
flea_crc16_ccit_compute(flea_u16_t crc_init, const flea_u8_t *data, flea_dtl_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
