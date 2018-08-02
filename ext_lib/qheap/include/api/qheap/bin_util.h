#ifndef _qheap_bin_util__H_
#define _qheap_bin_util__H_

#define QHEAP__ENCODE_U16_LE(to_enc, res_ptr) \
  do {qheap_u8_t* ptr = (res_ptr); uint_fast16_t input = to_enc; \
      (ptr)[1] = (input) >> 8; (ptr)[0] = input & 0xFF;} while(0)

// TODO: MAKE INLINE FUNCTION:
#define QHEAP__DECODE_U16_LE(in_enc_ptr) \
  (((uint_fast16_t) (in_enc_ptr)[1] << 8) \
  | ((uint_fast16_t) ((in_enc_ptr)[0] & 0xFF)))


#define QHEAP__ENCODE_U16_BE(to_enc, res_ptr) \
  do {qheap_u8_t* ptr = (res_ptr); uint_fast16_t input = to_enc; \
      (ptr)[0] = (input) >> 8; (ptr)[1] = input & 0xFF;} while(0)

// TODO: MAKE INLINE FUNCTION:
#define QHEAP__DECODE_U16_BE(in_enc_ptr) \
  (((uint_fast16_t) (in_enc_ptr)[0] << 8) \
  | ((uint_fast16_t) ((in_enc_ptr)[1] & 0xFF)))


#define QHEAP_MIN(a, b) ((a) > (b) ? (b) : (a))

#endif /* h-guard */
