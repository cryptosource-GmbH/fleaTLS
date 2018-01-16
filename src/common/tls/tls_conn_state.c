/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_conn_state.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "internal/common/tls/tls_int.h"


#ifdef FLEA_HAVE_TLS

static void flea_tls_conn_state_t__unset_cipher_suite(flea_tls_conn_state_t* conn_state__pt)
{
# ifdef FLEA_HAVE_TLS_CS_CBC
  if(conn_state__pt->cipher_suite_config__t.cipher_suite_class__e == flea_cbc_cipher_suite)
  {
    FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(
      conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8,
      conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_key_size__u8
      + conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_key_size__u8
    );
  }
  else
# endif /* ifdef FLEA_HAVE_TLS_CS_CBC */
# ifdef FLEA_HAVE_TLS_CS_GCM
  if(conn_state__pt->cipher_suite_config__t.cipher_suite_class__e == flea_gcm_cipher_suite)
  {
    FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(
      conn_state__pt->suite_specific__u.gcm_conn_state__t.cipher_key__bu8,
      conn_state__pt->cipher_suite_config__t.suite_specific__u.gcm_config__t.fixed_iv_length__u8
      + conn_state__pt->cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_key_size__u8
    );
  }
  else
# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */
  { }
  conn_state__pt->cipher_suite_config__t.cipher_suite_class__e = flea_null_cipher_suite;
}

void flea_tls_conn_state_t__ctor_no_cipher(flea_tls_conn_state_t* conn_state__pt)
{
  conn_state__pt->cipher_suite_config__t.cipher_suite_class__e = flea_null_cipher_suite;
  conn_state__pt->reserved_iv_len__u8 = 0;
}

# ifdef FLEA_HAVE_TLS_CS_CBC
flea_err_e THR_flea_tls_conn_state_t__ctor_cbc_hmac(
  flea_tls_conn_state_t* conn_state__pt,
  flea_block_cipher_id_e block_cipher_id,
  flea_mac_id_e          mac_id,
  const flea_u8_t*       cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t*       mac_key__pcu8,
  flea_al_u8_t           mac_key_len__alu8,
  flea_al_u8_t           mac_size__alu8
)
{
  FLEA_THR_BEG_FUNC();
#  ifdef FLEA_HEAP_MODE

  FLEA_ALLOC_MEM_ARR(
    conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8,
    cipher_key_len__alu8 + mac_key_len__alu8
  );
  conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.mac_key__bu8 =
    conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8 + cipher_key_len__alu8;
#  endif /* ifdef FLEA_HEAP_MODE */
  conn_state__pt->reserved_iv_len__u8 = flea_block_cipher__get_block_size(block_cipher_id);
  conn_state__pt->cipher_suite_config__t.cipher_suite_class__e = flea_cbc_cipher_suite;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id           = block_cipher_id;
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
} /* THR_flea_tls_conn_state_t__ctor_cbc_hmac */

# endif /* ifdef FLEA_HAVE_TLS_CS_CBC */

# ifdef FLEA_HAVE_TLS_CS_GCM
flea_err_e THR_flea_tls_conn_state_t__ctor_gcm(
  flea_tls_conn_state_t* conn_state__pt,
  flea_ae_id_e           ae_cipher_id,
  const flea_u8_t*       cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t*       fixed_iv__pcu8,
  flea_al_u8_t           fixed_iv_len__alu8
)
{
  FLEA_THR_BEG_FUNC();

#  ifdef FLEA_HEAP_MODE
  // note: it is important to keep the order of fixed and record iv since they
  // will be combined for the complete nonce (fixed||record = salt||explicit)
  FLEA_ALLOC_MEM_ARR(
    conn_state__pt->suite_specific__u.gcm_conn_state__t.cipher_key__bu8,
    cipher_key_len__alu8 + fixed_iv_len__alu8 + FLEA_CONST_TLS_GCM_RECORD_IV_LEN
  );
  conn_state__pt->suite_specific__u.gcm_conn_state__t.fixed_iv__bu8 =
    conn_state__pt->suite_specific__u.gcm_conn_state__t.cipher_key__bu8 + cipher_key_len__alu8;
  conn_state__pt->suite_specific__u.gcm_conn_state__t.record_iv__bu8 =
    conn_state__pt->suite_specific__u.gcm_conn_state__t.cipher_key__bu8 + cipher_key_len__alu8 + fixed_iv_len__alu8;
#  endif /* ifdef FLEA_HEAP_MODE */
  conn_state__pt->reserved_iv_len__u8 = FLEA_CONST_TLS_GCM_RECORD_IV_LEN;
  // conn_state__pt->cipher_suite_config__t.cipher_suite_id = ;
  conn_state__pt->cipher_suite_config__t.cipher_suite_class__e = flea_gcm_cipher_suite;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_id = ae_cipher_id;

  conn_state__pt->cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_key_size__u8  = cipher_key_len__alu8;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.gcm_config__t.fixed_iv_length__u8  = fixed_iv_len__alu8;
  conn_state__pt->cipher_suite_config__t.suite_specific__u.gcm_config__t.record_iv_length__u8 =
    FLEA_CONST_TLS_GCM_RECORD_IV_LEN;

  conn_state__pt->sequence_number__au32[0] = 0;
  conn_state__pt->sequence_number__au32[1] = 0;
  memcpy(
    conn_state__pt->suite_specific__u.gcm_conn_state__t.cipher_key__bu8,
    cipher_key__pcu8,
    cipher_key_len__alu8
  );
  memcpy(
    conn_state__pt->suite_specific__u.gcm_conn_state__t.fixed_iv__bu8,
    fixed_iv__pcu8,
    fixed_iv_len__alu8
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_conn_state_t__ctor_gcm */

# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */

void flea_tls_conn_state_t__dtor(flea_tls_conn_state_t* conn_state__pt)
{
  flea_tls_conn_state_t__unset_cipher_suite(conn_state__pt);
}

#endif /* ifdef FLEA_HAVE_TLS */
