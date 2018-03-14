/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_psk__H_
#define _flea_tls_psk__H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS_CS_PSK

// TODO: -> build cfg
# define FLEA_PSK_MAX_IDENTITY_LEN 256 // actually 2^16-1 in the standard

// so far only affects the buffer when reading the identity / identity hint

typedef struct
{
  flea_u8_t* psk_identity__u8;
  flea_u8_t  psk_identity_len__u8;
  flea_u8_t* psk_key__u8;
  flea_u8_t  psk_key_len__u8;
} flea_tls__psk_key_t;

#endif // ifdef FLEA_HAVE_TLS_CS_PSK

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
