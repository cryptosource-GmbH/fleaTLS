/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_psk__H_
#define _flea_tls_psk__H_

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Callback function that will be called during handshake to determine the PSK
 * that the server will use.
 *
 * @param[in] psk_lookup_ctx_mbn__vp Arbitrary object that is intended to be
 * used to lookup the PSK. E.g. a database handle.
 * @param[in] psk_identity__pu8 Identity of the client.
 * @param[in] psk_identity_len__u16 Length of the identity.
 * @param[out] psk_vec__t Contains the pre-shared key after the call.
 */
typedef flea_err_e (* flea_get_psk_cb_f)(
  const void*      psk_lookup_ctx_mbn__vp,
  const flea_u8_t* psk_identity__pu8,
  const flea_u16_t psk_identity_len__u16,
  flea_byte_vec_t* psk_vec__t
);

/**
 * Creates a TLS server object and is similar to THR_flea_tls_server_ctx_t__ctor
 * but has some additional arguments for PSK. Only the additional parameters are
 * described here.
 *
 * @param [in] identity_hint_mbn__pu8 Pointer to the identity hint that will be
 * sent to clients.
 * @param [in] identity_hint_len__u16 Length of the identity hint
 * @param [in] get_psk_mbn_cb__f Callback function to determine the PSK
 * @param [in] psk_lookup_ctx_mbn__vp Arbitrary object, e.g. a database, that
 * can be used to determine the PSK in the callback function.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_server_ctx_t__ctor_psk(
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
  const flea_u8_t*                  identity_hint_mbn__pu8,
  flea_u16_t                        identity_hint_len__u16,
  flea_get_psk_cb_f                 get_psk_mbn_cb__f,
  const void*                       psk_lookup_ctx_mbn__vp,
  flea_tls_flag_e                   flags,
  flea_tls_session_mngr_t*          session_mngr_mbn
);

// the above functions are also needed when the PSK flag is disabled

#ifdef FLEA_HAVE_TLS_CS_PSK

/*
 * Callback function that will be called during the handshake to transform the
 * PSK according to the identity hint provided by the server.
 *
 * @param[in,out] psk_vec__t Contains the untransformed PSK before the call and
 * the transformed PSK after the call.
 * @param[in] psk_identity_hint__pu8 Identity hint from server.
 * @param[in] psk_identity_hint_len__u16 The length of the identity hint.
 */
typedef flea_err_e (* flea_process_identity_hint_cb_f)(
  flea_byte_vec_t* psk_vec__t,
  const flea_u8_t* psk_identity_hint__pu8,
  const flea_u16_t psk_identity_hint_len__u16
);


/*
 * Creates a TLS client object where only PSK cipher suites are enabled.
 *
 * @param[in,out] tls_client_ctx  the ctx object to create
 * @param[in] rw_stream a read-write stream object which realizes the data and must
 * be implemented by the client code.
 * @param[in] psk__pu8 The pre-shared key that will be used.
 * @param[in] psk_len__u16 Length of the pre-shared key.
 * @param[in] psk_identity__pu8 Identity of the client.
 * @param[in] psk_identity_len__u16 Length of the identity.
 * @param[in] process_identity_hint_mbn_cb__f Callback function that will be
 * used during the handshake to process the server identity hint.
 * @param[in] server_name_mbn name of the server. This parameter may be set to
 * null if no hostname verification shall be carried out. If set as non-null,
 * then in accordance with the value of the parameter host_name_id, this can be * either a DNS name of an IP address. A DNS name is provided as a non-null
 * terminated ASCII string within the ref. fleaTLS performs byte-wise comparison
 * of the hostname but also interprets wildcard characters ('*'). An IP address
 * is provided as an encoded byte array. I.e. an IPv4 address 127.0.0.1 is
 * provided as the four byte array {0x7F, 0x00, 0x00, 0x01}. An IPv6 address is
 * provided analogously as a 16 byte array.
 * @param[in] host_name_id specifies whether a  DNS name or an IP address
 * is used as the hostname to verify. If server_name_mbn is set to null,
 * then the value of this parameter is not interpreted.
 * @param [in] allowed_cipher_suites a list of the TLS cipher suites the client
 * may negotiate.
 * @param [in] allowed_cipher_suites_len The length of allowed_cipher_suites.
 * @param[in] flags A combination of flags to control the client's behaviour.
 *
 * @return an error code
 */

flea_err_e THR_flea_tls_client_ctx_t__ctor_psk(
  flea_tls_client_ctx_t*            tls_client_ctx__pt,
  flea_rw_stream_t*                 rw_stream__pt,
  flea_u8_t*                        psk__pu8,
  flea_u16_t                        psk_len__u16,
  flea_u8_t*                        psk_identity__pu8,
  flea_u16_t                        psk_identity_len__u16,
  flea_process_identity_hint_cb_f   process_identity_hint_mbn_cb__f,
  const flea_ref_cu8_t*             server_name__pcrcu8,
  flea_host_id_type_e               host_name_id__e,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites__pe,
  flea_al_u16_t                     nb_allowed_cipher_suites__alu16,
  flea_tls_flag_e                   flags__e
);

#endif // ifdef FLEA_HAVE_TLS_CS_PSK

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
