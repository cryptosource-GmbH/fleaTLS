/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_psk__H_
#define _flea_tls_psk__H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS_CS_PSK

typedef struct
{
  flea_u8_t* identity__pu8;
  flea_u16_t identity_len__u16;
  flea_u8_t* psk__pu8;
  flea_u16_t psk_len__u16;
} flea_tls_psk_t;

typedef flea_err_e (* flea_get_psk_mbn_cb_f)(
  const void*,
  const flea_u8_t*,
  const flea_u16_t,
  flea_u8_t*,
  flea_u16_t*
);
typedef void (* flea_process_identity_hint_mbn_cb_f)(
  flea_tls_psk_t*,
  const flea_u8_t*,
  const flea_u16_t
);


#endif // ifdef FLEA_HAVE_TLS_CS_PSK

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
