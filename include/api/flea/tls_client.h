/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#ifndef _flea_tls_client__H_
# define _flea_tls_client__H_

# include "internal/common/default.h"
# include "internal/common/tls/tls_int.h"
# include "flea/privkey.h"
# include "internal/common/tls/tls_rec_prot.h"
# include "flea/cert_store.h"
# include "internal/common/tls/hostn_ver_int.h"
# include "flea/tls_client_session.h"
# include "flea/tls.h"
# include "flea/tls_fwd.h"

# ifdef FLEA_HAVE_TLS_CLIENT

#  ifdef __cplusplus
extern "C" {
#  endif


/**
 * Init a TLS client object.
 *
 * @param ctx pointer to the client ctx object to init
 */
#  define flea_tls_clt_ctx_t__INIT(ctx) do {memset((ctx), 0, sizeof(*(ctx)));} while(0)

/**
 * Destroy a TLS client context object.
 *
 * @param[in,out] tls_client_ctx The context object to destroy.
 */
void flea_tls_clt_ctx_t__dtor(flea_tls_clt_ctx_t* tls_client_ctx);

/**
 * Create a TLS client object. This implies the execution of the initial
 * TLS handshake. After the call to this function, data can be exchanged over
 * the TLS connection. All pointer type parameters that are supplied to this function must stay valid for the
 * complete life-cycle of this TLS client context object as they are used as
 * references within the TLS functions.
 *
 * @param[in,out] tls_client_ctx  the ctx object to create
 * @param[in] rw_stream a read-write stream object which realizes the data and must
 * be implemented by the client code.
 * transmission, i.e. typically via the TCP/IP sockets.
 * @param[in] trust_store The certificate trust store which contains trusted
 * certificates which are accepted as trusted root certificates when validating
 * the server's certificate chain.
 * @param[in] server_name_mbn name of the server. This parameter may be set to
 * null if no hostname verification shall be carried out. If set as non-null,
 * then in accordance with the value of the parameter host_name_id, this can be
 * either a DNS name of an IP address. A DNS name is provided as a non-null
 * terminated ASCII string within the ref. fleaTLS performs byte-wise comparison
 * of the hostname but also interprets wildcard characters ('*'). An IP address
 * is provided as an encoded byte array. I.e. an IPv4 address 127.0.0.1 is
 * provided as the four byte array {0x7F, 0x00, 0x00, 0x01}. An IPv6 address is
 * provided analogously as a 16 byte array.
 * @param[in] host_name_id specifies whether a  DNS name or an IP address
 * is used as the hostname to verify. If server_name_mbn is set to null,
 * then the value of this parameter is not interpreted.
 * @param[in] cert_chain_mbn The certificate chain the client uses for client
 * authentication. Each flea_ref_cu8_t refers to a DER encoded certificate of
 * the chain. The order of the certificates, starting from position 0, is
 * <client-cert> [ <ca-cert> <ca-cert> ] <root-cert>. The occurrence of CA certs
 * is optional. The root-cert may also be omitted according to the TLS standard.
 * This parameter may NULL,
 * then the client does not support client authentication.
 * @param[in] cert_chain_len the length of cert_chain_mbn. Set this to 0 if
 * cert_chain_mbn is NULL.
 * @param[in] private_key_mbn The client's private key associated with its
 * certificate. Must be provided if cert_chain_mbn is not NULL. Otherwise it
 * must be set to NULL.
 * @param[in] crls A list of DER encoded CRLs which the client uses for revocation
 * checking (according to the flags parameter, see below) of
 * the server's certificate chain.
 * @param[in] crls_len The length of crls.
 * @param[in] allowed_cipher_suites a list of the TLS cipher suites the client
 * may negotiate.
 * @param[in] allowed_cipher_suites_len The length of allowed_cipher_suites.
 * @param[in] allowed_ecc_curves A list of the ECC curves that are supported by the
 * client.
 * @param[in] allowed_ecc_curves_len The length of allowed_ecc_curves.
 * @param[in] allowed_sig_algs A list of allowed signature algorithms that the
 * server may use for digital signatures during the handshake and in its own
 * certificate chain.
 * @param allowed_sig_algs_len The length of allowed_sig_algs
 * @param[in] flags A combination of flags to control the client's behaviour.
 * @param[in,out] session_mbn A session object which holds the session information for resumption.
 * Upon input, this may be a constructed flea_tls_clt_session_t object
 * without any content or it may be one which already contains a session. In the
 * latter case, this function will attempt to use session resumption during the
 * initial handshake. In any case, during the life-cycle of this TLS client context
 * object, it receives the data of the most recent established TLS
 * session for later resumption. The object may be NULL if the session
 * resumption functionality shall not be used. However, if it is non-null, then
 * it must be a constructed object.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_clt_ctx_t__ctor(
  flea_tls_clt_ctx_t*               tls_client_ctx,
  flea_rw_stream_t*                 rw_stream,
  const flea_cert_store_t*          trust_store,
  const flea_ref_cu8_t*             server_name_mbn,
  flea_host_id_type_e               host_name_id,
  flea_ref_cu8_t*                   cert_chain_mbn,
  flea_al_u8_t                      cert_chain_len,
  flea_privkey_t*                   private_key_mbn,
  const flea_ref_cu8_t*             crls,
  flea_al_u16_t                     crls_len,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites,
  flea_al_u16_t                     allowed_cipher_suites_len,
  const flea_ec_dom_par_id_e*       allowed_ecc_curves,
  flea_al_u16_t                     allowed_ecc_curves_len,
  const flea_tls_sigalg_e*          allowed_sig_algs,
  flea_al_u16_t                     allowed_sig_algs_len,
  flea_tls_flag_e                   flags,
  flea_tls_clt_session_t*           session_mbn
) FLEA_ATTRIB_UNUSED_RESULT;


/**
 * Read application data over the TLS channel. If the connected server initiates a
 * renegotiation during the execution of this function, the renegotiation is
 * handled silently, i.e. depending of the configuration it is carried out or
 * declined.
 *
 * @param[in,out] tls_client_ctx The TLS client context object.
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
flea_err_e THR_flea_tls_clt_ctx_t__read_app_data(
  flea_tls_clt_ctx_t*     tls_client_ctx,
  flea_u8_t*              dta,
  flea_dtl_t*             dta_len,
  flea_stream_read_mode_e read_mode
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Send application data over the TLS channel. Note that this function may not
 * actually send the data over the underlying stream due to internal buffering. To enforce the sending of the written data, the
 * function THR_flea_tls_clt_ctx_t__flush_write_app_data() needs to be
 * called afterwards.
 *
 * @param[in] tls_client_ctx The TLS client object.
 * @param[in] dta The data to send.
 * @param[in] dta_len The length of dta.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_clt_ctx_t__send_app_data(
  flea_tls_clt_ctx_t* tls_client_ctx,
  const flea_u8_t*    dta,
  flea_dtl_t          dta_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Flush pending write data.
 *
 * @param[in] tls_client_ctx The TLS client object.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_clt_ctx_t__flush_write_app_data(flea_tls_clt_ctx_t* tls_client_ctx) FLEA_ATTRIB_UNUSED_RESULT;


/**
 * Test whether a tls client ctx is qualified for carrying out a
 * renegotiation based on its current status.
 *
 * @param[in] tls_client_ctx pointer to the client ctx object
 *
 * @return FLEA_TRUE if a renegotiation may be carried out, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_clt_ctx_t__is_reneg_allowed(flea_tls_clt_ctx_t* tls_client_ctx);

/**
 *
 * Initiate a renegotiation with potentially different parameters than in the previous handshake.
 * Before this function is called all pending application data or renegotiation requests
 * sent by the peer should be drained by a call to the read_app_data() function.
 * Otherwise, this function will return with an error because the pending stale TLS
 * records will be received instead of the handshake records belonging to the
 * renegotiation.
 *
 * @param[in] tls_client_ctx The TLS client object.
 * @param[out] result Is set to FLEA_FALSE if the renegotiation was declined
 * properly declined by a no-renegotiation-alert,
 * to FLEA_TRUE otherwise.
 * @param [in] trust_store the certificate trust store which contains trusted
 * certificates which are accepted as trusted root certificates when validating
 * the server's certificate chain
 * @param [in] cert_chain_mbn The certificate chain the client uses for client
 * authentication. Each flea_ref_cu8_t refers to a DER encoded certificate of
 * the chain. The order of the certificates, starting from position 0, is
 * <client-cert> [ <ca-cert> <ca-cert> ] <root-cert>. This parameter may NULL,
 * then the client does not support client authentication.
 * @param [in] cert_chain_len the length of cert_chain_mbn. Set this to 0 if
 * cert_chain_mbn is NULL.
 * @param [in] private_key_mbn The client's private key associated with its
 * certificate. Must be provided if cert_chain_mbn is not NULL. Otherwise it
 * must be set to NULL.
 * @param [in] allowed_cipher_suites a list of the TLS cipher suites the client
 * may negotiate.
 * @param [in] allowed_cipher_suites_len The length of allowed_cipher_suites.
 * @param [in] crls A list of DER encoded CRLs which the client uses for revocation
 * checking (according to the flags parameter, see below) of
 * the server's certificate chain.
 * @param [in] crls_len The length of crls.
 * @param [in] allowed_ecc_curves A list of the ECC curves that are supported by the
 * client.
 * @param [in] allowed_ecc_curves_len The length of allowed_ecc_curves.
 * @param [in] allowed_sig_algs A list of allowed signature algorithms that the
 * server may use for digital signatures during the handshake and in its own
 * certificate chain.
 * @param allowed_sig_algs_len The length of allowed_sig_algs.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_clt_ctx_t__renegotiate(
  flea_tls_clt_ctx_t*               tls_client_ctx,
  flea_bool_t*                      result,
  const flea_cert_store_t*          trust_store,
  flea_ref_cu8_t*                   cert_chain_mbn,
  flea_al_u8_t                      cert_chain_len,
  flea_privkey_t*                   private_key_mbn,
  const flea_ref_cu8_t*             crls,
  flea_al_u16_t                     crls_len,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites,
  flea_al_u16_t                     allowed_cipher_suites_len,
  const flea_ec_dom_par_id_e*       allowed_ecc_curves,
  flea_al_u16_t                     allowed_ecc_curves_len,
  const flea_tls_sigalg_e*          allowed_sig_algs,
  flea_al_u16_t                     allowed_sig_algs_len
) FLEA_ATTRIB_UNUSED_RESULT;

#  ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

/**
 * Find out if the peer's EE certificate is available. In case the connection
 * was established using session
 * resumption, the certificate will not be available.
 *
 * @param client_ctx the TLS client context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_clt_ctx_t__have_peer_ee_cert_ref(flea_tls_clt_ctx_t* client_ctx);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the peer's EE certificate from
 * the most recent handshake.
 *
 * @param client_ctx the TLS client context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t object if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_clt_ctx_t__get_peer_ee_cert_ref(flea_tls_clt_ctx_t* client_ctx);
#  endif // ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF

#  ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

/**
 * Find out if the trusted root certificate used to authenticate the peer is available. In case the connection
 * was established using session
 * resumption, the certificate will not be available.
 *
 * @param client_ctx the TLS client context object pointer
 *
 * @return FLEA_TRUE if the peer EE certificate is available, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_tls_clt_ctx_t__have_peer_root_cert_ref(flea_tls_clt_ctx_t* client_ctx);

/**
 * Get a pointer to the flea_x509_cert_ref_t of the trusted root certificate that was
 * used to authenticate the peer in the most recent handshake.
 *
 * @param client_ctx the TLS client context object pointer
 *
 * @return a pointer to the flea_x509_cert_ref_t object if it is available or
 * NULL otherwise.
 */
const flea_x509_cert_ref_t* flea_tls_clt_ctx_t__get_peer_root_cert_ref(flea_tls_clt_ctx_t* client_ctx);
#  endif // ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF


#  ifdef __cplusplus
}
#  endif

# endif // ifdef FLEA_HAVE_TLS_CLIENT
#endif /* h-guard */
