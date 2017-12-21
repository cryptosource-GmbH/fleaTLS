/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_server__H_
#define _flea_tls_server__H_

#include "flea/tls.h"
#include "internal/common/tls/tls_int.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS_SERVER

# define flea_tls_server_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)


void flea_tls_server_ctx_t__dtor(flea_tls_server_ctx_t* tls_server_ctx__pt);

/**
 *
 * @param allowed_cipher_suites a pointer to the array containing the
 * cipher suites supported by the server. The lower the index of a suite within
 * the array, the higher is its priority.
 */
flea_err_e THR_flea_tls_server_ctx_t__ctor(
  flea_tls_server_ctx_t*            tls_ctx,
  flea_rw_stream_t*                 rw_stream,
  const flea_ref_cu8_t*             cert_chain,
  flea_al_u8_t                      cert_chain_len,
  flea_private_key_t*               private_key,
  const flea_cert_store_t*          trust_store,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites,
  flea_al_u16_t                     nb_allowed_cipher_suites,
  const flea_ref_cu8_t*             crl_der,
  flea_al_u16_t                     nb_crls,
  flea_tls_session_mngr_t*          session_mngr_mbn,
  flea_ec_dom_par_id_e*             allowed_ecc_curves,
  flea_al_u16_t                     nb_allowed_curves,
  flea_tls_sigalg_e*                allowed_sig_algs,
  flea_al_u16_t                     nb_allowed_sig_algs,
  flea_tls_flag_e                   flags
);

flea_err_e THR_flea_tls_server_ctx_t__read_app_data(
  flea_tls_server_ctx_t*  tls_ctx_t,
  flea_u8_t*              data,
  flea_dtl_t*             data_len,
  flea_stream_read_mode_e rd_mode
);

flea_err_e THR_flea_tls_server_ctx_t__send_app_data(
  flea_tls_server_ctx_t* tls_ctx,
  const flea_u8_t*       data,
  flea_dtl_t             data_len__dtl
);


flea_err_e THR_flea_tls_server_ctx_t__flush_write_app_data(flea_tls_server_ctx_t* tls_ctx);


/**
 * Test whether a tls server ctx is qualified for carrying out a
 * renegotiation.
 *
 * @param tls_server_ctx__pt pointer to the server ctx object
 *
 * @return FLEA_TRUE if a renegotiation may be carried out, FLEA_FALSE
 * otherwise.
 */
flea_bool_e flea_tls_server_ctx_t__is_reneg_allowed(flea_tls_server_ctx_t* tls_server_ctx__pt);


flea_err_e THR_flea_tls_server_ctx_t__renegotiate(
  flea_tls_server_ctx_t*            tls_ctx,
  flea_bool_e*                      result,
  const flea_cert_store_t*          trust_store,
  const flea_ref_cu8_t*             cert_chain,
  flea_al_u8_t                      cert_chain_len,
  flea_private_key_t*               private_key,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites,
  flea_al_u16_t                     allowed_cipher_suites_len,
  const flea_ref_cu8_t*             crls,
  flea_al_u16_t                     crls_len,
  flea_ec_dom_par_id_e*             allowed_ecc_curves,
  flea_al_u16_t                     allowed_curves_len,
  flea_tls_sigalg_e*                allowed_sig_algs,
  flea_al_u16_t                     allowed_sig_algs_len
);


# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

/**
 * Find out if the peer's EE certificate is available.
 *
 * @param server_ctx__pt the TLS server context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_e flea_tls_server_ctx_t__have_peer_ee_cert_ref(flea_tls_server_ctx_t* server_ctx__pt);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the peer's EE certificate.
 *
 * @param server_ctx__pt the TLS server context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t oject if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_server_ctx_t__get_peer_ee_cert_ref(flea_tls_server_ctx_t* server_ctx__pt);
# endif // ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

/**
 * Find out if the trusted certificate used to authenticate the peer is available.
 *
 * @param server_ctx__pt the TLS server context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_e flea_tls_server_ctx_t__have_peer_root_cert_ref(flea_tls_server_ctx_t* server_ctx__pt);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the trusted certificate that was
 * used to authenticate the peer.
 *
 * @param server_ctx__pt the TLS server context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t oject if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_server_ctx_t__get_peer_root_cert_ref(flea_tls_server_ctx_t* server_ctx__pt);
# endif // ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

#endif // ifdef FLEA_HAVE_TLS_SERVER

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
