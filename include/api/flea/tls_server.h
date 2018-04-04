/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_server__H_
#define _flea_tls_server__H_

#include "internal/common/default.h"
#include "flea/tls.h"
#include "internal/common/tls/tls_int.h"
#include "flea/tls_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS_SERVER

# define flea_tls_server_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)


void flea_tls_server_ctx_t__dtor(flea_tls_server_ctx_t* tls_server_ctx);


/**
 * Create a TLS server object for a connection to a client. This implies the execution of the initial
 * TLS handshake. After the call to this function, data can be exchanged over
 * the TLS connection. All pointer type parameters that are supplied to this function must stay valid for the
 * complete life-cycle of this TLS server context object as they are used as
 * references.
 *
 * @param[in,out] tls_server_ctx  The TLS server ctx object to create.
 * @param[in,out] rw_stream The stream which implements the underlying
 * bidirectional data transfer. Has to be implemented by client code.
 * @param [in] trust_store_mbn Pointer to a certificate store object which
 * contains the trusted certificates the server may use to authenticate client
 * certificates. If this parameter is non-null, then the server enforces client
 * authentication. It may also be null, then the server does not request client
 * authentication.
 * @param[in] cert_chain The certificate chain the server uses for server
 * authentication. Each flea_ref_cu8_t refers to a DER encoded certificate of
 * the chain. The order of the certificates, starting from position 0, is
 * <server-cert> [ <ca-cert> <ca-cert> ] <root-cert>. The occurrence of CA certs
 * is optional. The root-cert may also be omitted according to the TLS standard.
 * @param[in] cert_chain_len the length of cert_chain.
 * @param allowed_cipher_suites a pointer to the array containing the
 * cipher suites supported by the server. The lower the index of a suite within
 * the array, the higher is its priority.
 * @param[in] private_key The server's private key associated with its
 * certificate.
 * @param[in] crls A list of DER encoded CRLs which the server uses for revocation
 * checking (according to the flags parameter, see below) of
 * the client's certificate chain.
 * @param[in] crls_len The length of crls.
 * @param[in] allowed_cipher_suites a list of the TLS cipher suites the server
 * may negotiate ordered in descending priority.
 * @param[in] allowed_cipher_suites_len The length of allowed_cipher_suites.
 * @param[in] allowed_ecc_curves A list of the ECC curves that are supported by the
 * server ordered in descending priority.
 * @param[in] allowed_ecc_curves_len The length of allowed_ecc_curves.
 * @param[in] allowed_sig_algs A list of allowed signature algorithms that the
 * server may use for digital signatures during the handshake and in its own
 * certificate chain. It is ordered in descending priority.
 * @param allowed_sig_algs_len The length of allowed_sig_algs
 * @param[in] flags A combination of flags to control the server's behaviour.
 * @param[in,out] session_mngr_mbn A session manager implementing a TLS session
 * cache used to store sessions
 * established with clients for later resumption. This object may be shared
 * between different threads in which different flea_tls_server_ctx_t objects handle different connections to different clients. Once a client connects and requests connection resumption, the server performs a lookup in the flea_tls_session_mngr_t object. If the session is in the cache, the server accepts the resumption.  This parameter may be null, in which case the server does not support session resumption.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_server_ctx_t__ctor(
  flea_tls_server_ctx_t*            tls_server_ctx,
  flea_rw_stream_t*                 rw_stream,
  const flea_cert_store_t*          trust_store_mbn,
  const flea_ref_cu8_t*             cert_chain,
  flea_al_u8_t                      cert_chain_len,
  flea_private_key_t*               private_key,
  const flea_ref_cu8_t*             crls,
  flea_al_u16_t                     crls_len,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites,
  flea_al_u16_t                     allowed_cipher_suites_len,
  flea_ec_dom_par_id_e*             allowed_ecc_curves,
  flea_al_u16_t                     allowed_ecc_curves_len,
  flea_tls_sigalg_e*                allowed_sig_algs,
  flea_al_u16_t                     allowed_sig_algs_len,
  flea_tls_flag_e                   flags,
  flea_tls_session_mngr_t*          session_mngr_mbn
);

/**
 * Read application data over the TLS channel. If the connected client initiates a
 * renegotiation during the execution of this function, the renegotiation is
 * handled silently, i.e. depending of the configuration it is carried out or
 * declined.
 *
 * @param[in,out] tls_server_ctx The TLS server context object.
 * @param[out] dta Pointer to the buffer which should receive the data.
 * @param[in,out] dta_len Pointer to the length of the data to be read. dta
 * must have at least as much space reserved as this value is on input. The function will return data up to the length of this input value. Depending on the chosen
 * read_mode, less data may be returned. The length of *dta_len is updated by
 * this function to the number of actually read bytes.
 * @param[in] read_mode the mode in which to read data from over the TLS
 * channel.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_server_ctx_t__read_app_data(
  flea_tls_server_ctx_t*  tls_server_ctx,
  flea_u8_t*              dta,
  flea_dtl_t*             dta_len,
  flea_stream_read_mode_e read_mode
);

/**
 * Send application data over the TLS channel. Note that this function may not
 * actually send the data over the underlying stream due to internal buffering. To enforce the sending of the written data, the
 * function THR_flea_tls_server_ctx_t__flush_write_app_data() needs to be
 * called afterwards.
 *
 * @param[in] tls_server_ctx The TLS server object.
 * @param[in] dta The data to send.
 * @param[in] dta_len The length of dta.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_server_ctx_t__send_app_data(
  flea_tls_server_ctx_t* tls_server_ctx,
  const flea_u8_t*       dta,
  flea_dtl_t             dta_len
);


flea_err_e THR_flea_tls_server_ctx_t__flush_write_app_data(flea_tls_server_ctx_t* tls_ctx);


/**
 * Test whether a tls server ctx is qualified for carrying out a
 * renegotiation.
 *
 * @param [in,out] tls_server_ctx Pointer to the server ctx object.
 *
 * @return FLEA_TRUE if a renegotiation may be carried out, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_server_ctx_t__is_reneg_allowed(flea_tls_server_ctx_t* tls_server_ctx);

/**
 *
 * Initiate a renegotiation with potentially different parameters than in the previous handshake.
 * Before this function is called all pending application data or renegotiation requests
 * sent by the peer should be drained by a call to the read_app_data() function.
 * Otherwise, this function will return with an error because the pending stale TLS
 * records will be received instead of the handshake records belonging to the
 * renegotiation.
 *
 * @param [in,out] tls_server_ctx Pointer to the server ctx object.
 * @param [out] result pointer to a boolean, which upon function return
 * indicates whether the renegotiation was carried actually out. If the
 * renegotiation was carried out, it takes on the value FLEA_TRUE. Otherwise, if
 * the renegotiation was refused, it
 * becomes FLEA_FALSE.
 * @param [in] trust_store_mbn Pointer to a certificate store object which
 * contains the trusted certificates the server may use to authenticate client
 * certificates. If this parameter is non-null, then the server enforces client
 * authentication. It may also be null, then the server does not request client
 * authentication.
 * @param[in] cert_chain The certificate chain the server uses for server
 * authentication. Each flea_ref_cu8_t refers to a DER encoded certificate of
 * the chain. The order of the certificates, starting from position 0, is
 * <server-cert> [ <ca-cert> <ca-cert> ] <root-cert>. The occurrence of CA certs
 * is optional. The root-cert may also be omitted according to the TLS standard.
 * @param allowed_cipher_suites a pointer to the array containing the
 * cipher suites supported by the server. The lower the index of a suite within
 * the array, the higher is its priority.
 * @param[in] cert_chain_len the length of cert_chain.
 * @param[in] private_key The server's private key associated with its
 * certificate.
 * @param[in] crls A list of DER encoded CRLs which the server uses for revocation
 * checking (according to the flags parameter, see below) of
 * the client's certificate chain.
 * @param[in] crls_len The length of crls.
 * @param[in] allowed_cipher_suites a list of the TLS cipher suites the server
 * may negotiate ordered in descending priority.
 * @param[in] allowed_cipher_suites_len The length of allowed_cipher_suites.
 * @param[in] allowed_ecc_curves A list of the ECC curves that are supported by the
 * server ordered in descending priority.
 * @param[in] allowed_ecc_curves_len The length of allowed_ecc_curves.
 * @param[in] allowed_sig_algs A list of allowed signature algorithms that the
 * server may use for digital signatures during the handshake and in its own
 * certificate chain. It is ordered in descending priority.
 * @param allowed_sig_algs_len The length of allowed_sig_algs
 * cache used to store sessions
 * established with clients for later resumption. This object may be shared
 * between different threads in which different flea_tls_server_ctx_t objects handle different connections to different clients. Once a client connects and requests connection resumption, the server performs a lookup in the flea_tls_session_mngr_t object. If the session is in the cache, the server accepts the resumption.  This parameter may be null, in which case the server does not support session resumption.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_server_ctx_t__renegotiate(
  flea_tls_server_ctx_t*            tls_server_ctx,
  flea_bool_t*                      result,
  const flea_cert_store_t*          trust_store_mbn,
  const flea_ref_cu8_t*             cert_chain,
  flea_al_u8_t                      cert_chain_len,
  flea_private_key_t*               private_key,
  const flea_ref_cu8_t*             crls,
  flea_al_u16_t                     crls_len,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites,
  flea_al_u16_t                     allowed_cipher_suites_len,
  flea_ec_dom_par_id_e*             allowed_ecc_curves,
  flea_al_u16_t                     allowed_ecc_curves_len,
  flea_tls_sigalg_e*                allowed_sig_algs,
  flea_al_u16_t                     allowed_sig_algs_len
);


# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

/**
 * Find out if the peer's EE certificate is available.
 *
 * @param server_ctx the TLS server context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_server_ctx_t__have_peer_ee_cert_ref(flea_tls_server_ctx_t* server_ctx);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the peer's EE certificate.
 *
 * @param server_ctx the TLS server context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t object if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_server_ctx_t__get_peer_ee_cert_ref(flea_tls_server_ctx_t* server_ctx);
# endif // ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

/**
 * Find out if the trusted certificate used to authenticate the peer is available.
 *
 * @param server_ctx the TLS server context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_server_ctx_t__have_peer_root_cert_ref(flea_tls_server_ctx_t* server_ctx);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the trusted certificate that was
 * used to authenticate the peer.
 *
 * @param server_ctx the TLS server context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t object if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_server_ctx_t__get_peer_root_cert_ref(flea_tls_server_ctx_t* server_ctx);
# endif // ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

#endif // ifdef FLEA_HAVE_TLS_SERVER

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
