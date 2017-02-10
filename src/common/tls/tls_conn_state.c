/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */
#include "internal/common/tls_conn_state.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/util.h"


static void flea_tls_conn_state_t__unset_cipher_suite(flea_tls_conn_state_t* conn_state__pt)
{
  if(conn_state__pt->cipher_suite_config__t.cipher_suite_id == TLS_RSA_WITH_AES_256_CBC_SHA256)
  {
    FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(
      conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8,
      conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_key_size__u8
      + conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_key_size__u8
    );
  }
  conn_state__pt->cipher_suite_config__t.cipher_suite_id = TLS_NULL_WITH_NULL_NULL;
}

void flea_tls_conn_state_t__ctor_no_cipher(flea_tls_conn_state_t* conn_state__pt)
{
  conn_state__pt->cipher_suite_config__t.cipher_suite_id = TLS_NULL_WITH_NULL_NULL;
}

flea_err_t THR_flea_tls_conn_state_t__ctor_cbc_hmac(
  flea_tls_conn_state_t* conn_state__pt,
  flea_block_cipher_id_t block_cipher_id,
  flea_hash_id_t         hash_id, // ????
  flea_mac_id_t          mac_id,
  const flea_u8_t*       cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t*       mac_key__pcu8,
  flea_al_u8_t           mac_key_len__alu8,
  flea_al_u8_t           mac_size__alu8
)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(
    conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8,
    cipher_key_len__alu8 + mac_key_len__alu8
  );
  conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.mac_key__bu8 =
    conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8 + cipher_key_len__alu8;
#endif
  conn_state__pt->cipher_suite_config__t.cipher_suite_id = TLS_RSA_WITH_AES_256_CBC_SHA256;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id           = block_cipher_id;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.hash_id             = hash_id;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_size__u8        = mac_size__alu8;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_key_size__u8    = mac_key_len__alu8;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_key_size__u8 =
    cipher_key_len__alu8;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_id = mac_id;

  conn_state__pt->sequence_number__au32[0] = 0;
  conn_state__pt->sequence_number__au32[1] = 0;
  memcpy(conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.mac_key__bu8, mac_key__pcu8, mac_key_len__alu8);
  memcpy(
    conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8,
    cipher_key__pcu8,
    cipher_key_len__alu8
  );

  FLEA_THR_FIN_SEC_empty();
}

void flea_tls_conn_state_t__dtor(flea_tls_conn_state_t* conn_state__pt)
{
  flea_tls_conn_state_t__unset_cipher_suite(conn_state__pt);
}
