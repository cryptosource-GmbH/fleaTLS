#ifndef _flea_tls_client__H_
#define _flea_tls_client__H_

#include "internal/common/tls/tls_int.h"
#include "flea/privkey.h"
#include "internal/common/tls_rec_prot.h"
#include "flea/cert_store.h"
#include "internal/common/hostn_ver_int.h"
#include "flea/tls_client_session.h"
#include "flea/tls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_tls_ctx_t                 tls_ctx__t;
  flea_hostn_validation_params_t hostn_valid_params__t;
} flea_tls_client_ctx_t;


#define flea_tls_ctx_t__INIT(__p)        do {memset((__p), 0, sizeof(*(__p)));} while(0)
#define flea_tls_client_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)

flea_err_t THR_flea_tls_client_ctx_t__ctor(
  flea_tls_client_ctx_t*     tls_ctx__pt,
  const flea_cert_store_t*   trust_store__pt,
  const flea_ref_cu8_t*      server_name__pcrcu8,
  flea_host_id_type_e        host_name_id__e,
  flea_rw_stream_t*          rw_stream__pt,
  flea_ref_cu8_t*            cert_chain_mbn__pt,
  flea_al_u8_t               cert_chain_len__alu8,
  flea_private_key_t*        private_key_mbn__pt,
  const flea_ref_cu16_t*     allowed_cipher_suites__prcu16,
  // TODO: TURN INTO REF_CU8
  const flea_byte_vec_t*     crl_der__pt,
  flea_al_u16_t              nb_crls__alu16,
  flea_tls_client_session_t* session_mbn__pt,
  flea_ref_cu8_t*            allowed_ecc_curves_ref__prcu8,
  flea_ref_cu8_t*            allowed_sig_algs_ref__prcu8,
  flea_al_u16_t              flags__alu16
);


void flea_tls_client_ctx_t__dtor(flea_tls_client_ctx_t* tls_client_ctx__pt);


flea_err_t THR_flea_tls_client_ctx_t__read_app_data(
  flea_tls_client_ctx_t*  tls_ctx_t,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
);
flea_err_t THR_flea_tls_client_ctx_t__send_app_data(
  flea_tls_client_ctx_t* tls_ctx,
  const flea_u8_t*       data,
  flea_u8_t              data_len
);

flea_err_t THR_flea_tls_client_ctx_t__flush_write_app_data(flea_tls_client_ctx_t* tls_ctx);


flea_err_t THR_flea_tls_client_ctx_t__renegotiate(
  flea_tls_client_ctx_t*   tls_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
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
flea_bool_t flea_tls_client_ctx_t__have_peer_ee_cert_ref(flea_tls_client_ctx_t* client_ctx__pt);

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
#endif

#ifdef __cplusplus
}
#endif
#endif /* h-guard */