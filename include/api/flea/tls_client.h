/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_client__H_
#define _flea_tls_client__H_

#include "internal/common/tls/tls_int.h"
#include "flea/privkey.h"
#include "internal/common/tls_rec_prot.h"
#include "flea/cert_store.h"
#include "internal/common/hostn_ver_int.h"
#include "flea/tls_client_session.h"
#include "flea/tls.h"
#include "internal/common/tls/tls_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif

struct struct_flea_tls_client_ctx_t
{
  flea_tls_ctx_t                 tls_ctx__t;
  flea_hostn_validation_params_t hostn_valid_params__t;
};


#define flea_tls_client_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)

flea_err_t THR_flea_tls_client_ctx_t__ctor(
  flea_tls_client_ctx_t*             tls_ctx,
  const flea_cert_store_t*           trust_store,
  const flea_ref_cu8_t*              server_name,
  flea_host_id_type_e                host_name_id,
  flea_rw_stream_t*                  rw_stream,
  flea_ref_cu8_t*                    cert_chain_mbn,
  flea_al_u8_t                       cert_chain_len,
  flea_private_key_t*                private_key_mbn,
  const flea_tls__cipher_suite_id_t* allowed_cipher_suites__pe,
  flea_al_u16_t                      nb_allowed_cipher_suites__alu16,
  const flea_ref_cu8_t*              crl_der,
  flea_al_u16_t                      nb_crls,
  flea_tls_client_session_t*         session_mbn,
  flea_ec_dom_par_id_t*              allowed_ecc_curves__pe,
  flea_al_u16_t                      nb_allowed_curves__alu16,
  flea_tls_sigalg_e*                 allowed_sig_algs,
  flea_al_u16_t                      nb_allowed_sig_algs,
  flea_al_u16_t                      flags
);


void flea_tls_client_ctx_t__dtor(flea_tls_client_ctx_t* tls_client_ctx__pt);


flea_err_t THR_flea_tls_client_ctx_t__read_app_data(
  flea_tls_client_ctx_t*  tls_ctx,
  flea_u8_t*              data,
  flea_al_u16_t*          data_len,
  flea_stream_read_mode_e rd_mode
);
flea_err_t THR_flea_tls_client_ctx_t__send_app_data(
  flea_tls_client_ctx_t* tls_ctx,
  const flea_u8_t*       data,
  flea_dtl_t             data_len
);

flea_err_t THR_flea_tls_client_ctx_t__flush_write_app_data(flea_tls_client_ctx_t* tls_ctx);


/**
 * Test whether a tls client ctx is qualified for carrying out a
 * renegotiation.
 *
 * @param tls_client_ctx__pt pointer to the client ctx object
 *
 * @return FLEA_TRUE if a renegotiation may be carried out, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_client_ctx_t__is_reneg_allowed(flea_tls_client_ctx_t* tls_client_ctx__pt);

/**
 *
 * Before this function is called all pending application data or renegotiation requests
 * sent by the peer should be drained by a call to the read_app_data() function.
 * Otherwise, this function will return with an error because the pending stale TLS
 * records will be received instead of the handshake records belonging to the
 * renegotiation.
 *
 *
 */
flea_err_t THR_flea_tls_client_ctx_t__renegotiate(
  flea_tls_client_ctx_t*             tls_ctx,
  flea_bool_t*                       result,
  const flea_cert_store_t*           trust_store,
  flea_ref_cu8_t*                    cert_chain,
  flea_al_u8_t                       cert_chain_len,
  const flea_tls__cipher_suite_id_t* allowed_cipher_suites__pe,
  flea_al_u16_t                      nb_allowed_cipher_suites__alu16,
  const flea_ref_cu8_t*              crl_der,
  flea_al_u16_t                      nb_crls
);

#ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

/**
 * Find out if the peer's EE certificate is available.
 *
 * @param client_ctx__pt the TLS client context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_client_ctx_t__have_peer_ee_cert_ref(flea_tls_client_ctx_t* client_ctx);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the peer's EE certificate.
 *
 * @param client_ctx__pt the TLS client context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t oject if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_client_ctx_t__get_peer_ee_cert_ref(flea_tls_client_ctx_t* client_ctx__pt);
#endif

#ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

/**
 * Find out if the trusted certificate used to authenticate the peer is available.
 *
 * @param client_ctx__pt the TLS client context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_client_ctx_t__have_peer_root_cert_ref(flea_tls_client_ctx_t* client_ctx__pt);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the trusted certificate that was
 * used to authenticate the peer.
 *
 * @param client_ctx__pt the TLS client context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t oject if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_client_ctx_t__get_peer_root_cert_ref(flea_tls_client_ctx_t* client_ctx__pt);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
