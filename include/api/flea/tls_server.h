/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_server__H_
#define _flea_tls_server__H_

#include "flea/tls.h"
#include "internal/common/tls/tls_int.h"
#include "flea/tls_shrd_server.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
  flea_tls_shared_server_ctx_t* shared_ctx__pt;
  flea_tls_ctx_t                tls_ctx__t;
} flea_tls_server_ctx_t;

#define flea_tls_server_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)

void flea_tls_server_ctx_t__dtor(flea_tls_server_ctx_t* tls_server_ctx__pt);

flea_err_t THR_flea_tls_server_ctx_t__ctor(
  flea_tls_server_ctx_t*        tls_ctx__pt,
  flea_tls_shared_server_ctx_t* shrd_server_ctx__pt,
  flea_rw_stream_t*             rw_stream__pt,
  flea_ref_cu8_t*               cert_chain__pt,
  flea_al_u8_t                  cert_chain_len__alu8,
  const flea_cert_store_t*      trust_store__t,
  const flea_ref_cu16_t*        allowed_cipher_suites__prcu16,
  flea_rev_chk_mode_e           rev_chk_mode__e,
  const flea_byte_vec_t*        crl_der__pt,
  flea_al_u16_t                 nb_crls__alu16,
  flea_tls_session_mngr_t*      session_mngr_mbn__pt,
  flea_tls_renegotiation_spec_e reneg_spec__e,
  flea_ref_cu8_t*               allowed_ecc_curves_ref__prcu8,
  flea_ref_cu8_t*               allowed_sig_algs_ref__prcu8,
  flea_tls_flag_e               flags
);

flea_err_t THR_flea_tls_server_ctx_t__read_app_data(
  flea_tls_server_ctx_t*  tls_ctx_t,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
);

flea_err_t THR_flea_tls_server_ctx_t__send_app_data(
  flea_tls_server_ctx_t* tls_ctx,
  const flea_u8_t*       data,
  flea_u8_t              data_len
);


flea_err_t THR_flea_tls_server_ctx_t__flush_write_app_data(flea_tls_server_ctx_t* tls_ctx);


flea_err_t THR_flea_tls_server_ctx_t__renegotiate(
  flea_tls_server_ctx_t*   tls_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  /* new session id? */
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  flea_rev_chk_mode_e      rev_chk_mode__e,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
);
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
