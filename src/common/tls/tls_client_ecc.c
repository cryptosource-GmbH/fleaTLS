/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls/tls_client_int_ecc.h"
#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/tls_session_mngr.h"
#include "flea/alloc.h"

#ifdef FLEA_HAVE_TLS_CLIENT

flea_err_e THR_flea_tls__send_client_key_exchange_ecdhe(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  flea_ref_cu8_t pub_point__rcu8;
  flea_u32_t hdr_len__u32;

  FLEA_THR_BEG_FUNC();


  pub_point__rcu8 = flea_public_key__get_encoded_public_component(hs_ctx__pt->ecdhe_pub_key__pt);
  hdr_len__u32    = pub_point__rcu8.len__dtl + 1;


  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      hdr_len__u32
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      (flea_u8_t*) &pub_point__rcu8.len__dtl,
      1
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      pub_point__rcu8.data__pcu8,
      pub_point__rcu8.len__dtl
    )
  );


  FLEA_THR_FIN_SEC(
    flea_public_key_t__dtor(hs_ctx__pt->ecdhe_pub_key__pt);
  );
} /* THR_flea_tls__send_client_key_exchange_ecdhe */

#endif /* ifdef FLEA_HAVE_TLS_CLIENT */
