/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_psk__H_
#define _flea_tls_psk__H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS_CS_PSK

// TODO: -> build cfg
# define FLEA_PSK_MAX_IDENTITY_LEN      128 //   MUST support 128 and can be up to 2^16
# define FLEA_PSK_MAX_IDENTITY_HINT_LEN 128 //
# define FLEA_PSK_MAX_PSK_LEN           64  //   MUST support 64 and can be up to 2^16

// so far only affects the buffer when reading the identity / identity hint

typedef struct
{
  flea_u8_t* identity__pu8;
  flea_u16_t identity_len__u16;
  flea_u8_t* psk__pu8;
  flea_u16_t psk_len__u16;
} flea_tls_psk_t;

#endif // ifdef FLEA_HAVE_TLS_CS_PSK

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
