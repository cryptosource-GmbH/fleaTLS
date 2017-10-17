/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls__H_
#define _flea_tls__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/pubkey.h"
#include "flea/hash.h"
#include "flea/mac.h"
#include "flea/rw_stream.h"
#include "internal/common/tls_ciph_suite.h"
// #include "internal/common/tls/tls_common.h"
#include "internal/common/tls_rec_prot.h"
#include "flea/util.h"
#include "flea/cert_store.h"
#include "internal/common/hostn_ver_int.h"
#include "flea/pk_api.h"
#include "internal/common/tls/tls_int.h"
#include "flea/tls_session_mngr.h"
#include "flea/tls_client_session.h"

#ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
extern "C" {
# endif

typedef enum
{
  flea_tls_flag__read_timeout_during_handshake = 1
} flea_tls_flag_e;

// defines for max sizes to allocate on the stack
// TODO: use values in algo_config.h?
// #define FLEA_TLS_MAX_RECORD_DATA_SIZE 16384 // 2^14 max record sizeof
// # define FLEA_TLS_MAX_PADDING_SIZE 255 // each byte must hold the padding value => 255 is max

// TODO: split up secure_reneg into ..._cert_fixed, cert_variable
typedef enum
{
  flea_tls_no_reneg,
  flea_tls_only_secure_reneg,
  flea_tls_allow_insecure_reneg
} flea_tls_renegotiation_spec_e;

typedef struct
{
  flea_rev_chk_mode_e    rev_chk_mode__e;
  const flea_byte_vec_t* crl_der__pt;
  flea_u16_t             nb_crls__u16;
} flea_revoc_chk_cfg_t;

# if 0

typedef struct
{
  // flea_tls__connection_end_t connection_end; /* Server or Client */


  /*flea_u8_t mac_length;
   * flea_u8_t mac_key_length;*/
  // CompressionMethod *compression_methods; /* Pool of compression methods that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  // flea_u32_t        compression_methods_len;
  // TODO: MAKE ABSTRACT BUFS:
  // flea_u8_t server_random [32];     /* random value that the server sends */
} flea_tls__security_parameters_t;
# endif // if 0

typedef struct
{
  flea_hash_id_t      hash_id__t;
  flea_pk_scheme_id_t pk_scheme_id__t;
} flea_tls__hash_sig_t;

/*typedef struct
 *  {
 *  flea_private_key_t private_key__t;
 *  } flea_tls_server_shared_ctx_t;
 *
 *  flea_tls_ctx_t*/

struct struct_flea_tls_ctx_t
{
  flea_tls__connection_end_t connection_end; /* Server or Client */

# ifdef FLEA_USE_STACK_BUF
  flea_u8_t                  master_secret__bu8[FLEA_TLS_MASTER_SECRET_SIZE]; /* symmetric keys are derived from this */
  // flea_u8_t  client_and_server_random__bu8 [2 * FLEA_TLS_HELLO_RANDOM_SIZE]; /* random value that the client sends */
# else
  flea_u8_t*                 master_secret__bu8;
  // flea_u8_t* client_and_server_random__bu8;
# endif

  // define 4 parameters independently instead of list of cipher suites
  const flea_ref_cu16_t*         allowed_cipher_suites__prcu16; /* Pool of ciphersuites that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  // flea_u8_t                    allowed_cipher_suites_len__u8;
  flea_u16_t                     selected_cipher_suite__u16; // TODO: change to cipher suite id type (already being used as such)

  flea_tls__protocol_version_t   version; /* max. supported TLS version */

  flea_hash_id_t                 prf_hash_id__t; // stores hash function to use for the PRF algorithm

  flea_tls__hash_sig_t           kex_hash_sig__t; // hash and sig algorithms used for KEX

  flea_rw_stream_t*              rw_stream__pt;
  flea_tls_rec_prot_t            rec_prot__t;
  const flea_cert_store_t*       trust_store__pt;
  // TODO: into client:
  flea_hostn_validation_params_t hostn_valid_params__t;
  // kann bleiben:
  flea_ref_cu8_t*                cert_chain_mbn__pt;
  flea_u8_t                      cert_chain_len__u8;

  // => SHARED_SERVER_CTX:
  flea_private_key_t             private_key__t;
  //
  // flea_tls_server_shared_ctx_t *server_shared_ctx__pt;
  // => client_ctx:
  flea_private_key_t*  private_key_for_client_mbn__pt;
  flea_revoc_chk_cfg_t rev_chk_cfg__t;
  flea_u8_t            sec_reneg_flag__u8;

  // => HANDSHAKE_CTX / CHECK IF USED AT ALL!
  // flea_private_key_t             ecdhe_priv_key__t; // server needs to store it until the client sends his pubkey
  // => HANDSHAKE_CTX / CHECK IF USED AT ALL!
  flea_public_key_t ecdhe_pub_key__t; // client needs to store it to send it afterwards

  // STAYS IN TLS_CTX:
# ifdef FLEA_USE_HEAP_BUF
  flea_u8_t*                 own_vfy_data__bu8;
  flea_u8_t*                 peer_vfy_data__bu8;
# else
  flea_u8_t                  own_vfy_data__bu8[12];
  flea_u8_t                  peer_vfy_data__bu8[12];
# endif
  flea_tls_client_session_t* client_session_mbn__pt;
  flea_tls_session_mngr_t*   session_mngr_mbn__pt;
  flea_tls_session_entry_t*  server_active_sess_mbn__pt;
  flea_u8_t                  server_resume_session__u8;
  flea_u8_t                  allow_reneg__u8;
  flea_u8_t                  allow_insec_reneg__u8;
  flea_u8_t                  extension_ctrl__u8;       /* used only by server */
  flea_ref_cu8_t             allowed_ecc_curves__rcu8; /* by flea_ec_dom_par_id_t */
  flea_u8_t                  chosen_ecc_dp_internal_id__u8;

  // chosen hash algorithm in sig_alg extension. Signature algorithm is fixed by
  // the loaded certificate
  flea_ref_cu8_t allowed_sig_algs__rcu8;
  flea_hash_id_t chosen_hash_algorithm__t; // use as hash alg when signing with private key (server and client)
  flea_bool_t    can_use_ecdhe;            // true if sig alg extension produces a match so we can sign the ECDHE params
  // flea_stream_read_mode_e    handshake_read_mode__e;
  // flea_tls_flag_e flags;
  // TODO: MAKE UNION WITH CLIENT PRIVATE KEY:
};

typedef struct
{
  flea_private_key_t server_private_key;
} flea_tls_shared_server_ctx_t;

typedef struct
{
  flea_tls_shared_server_ctx_t* shared_ctx__pt;
  flea_tls_ctx_t                tls_ctx__t;
} flea_tls_server_ctx_t;


# define flea_tls_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)

void flea_tls_ctx_t__dtor(flea_tls_ctx_t* tls_ctx__pt);

flea_err_t THR_flea_tls_ctx_t__ctor_client(
  flea_tls_ctx_t*               tls_ctx__pt,
  const flea_cert_store_t*      trust_store__pt,
  const flea_ref_cu8_t*         server_name__pcrcu8,
  flea_host_id_type_e           host_name_id__e,
  flea_rw_stream_t*             rw_stream__pt,

  /* const flea_u8_t*         session_id__pcu8,
   * flea_al_u8_t             session_id_len__alu8,*/
  flea_ref_cu8_t*               cert_chain_mbn__pt,
  flea_al_u8_t                  cert_chain_len__alu8,
  // flea_ref_cu8_t*               client_public_key__pt,
  flea_private_key_t*           private_key_mbn__pt,
  const flea_ref_cu16_t*        allowed_cipher_suites__prcu16,
  flea_rev_chk_mode_e           rev_chk_mode__e,
  const flea_byte_vec_t*        crl_der__pt,
  flea_al_u16_t                 nb_crls__alu16,
  flea_tls_client_session_t*    session_mbn__pt,
  flea_tls_renegotiation_spec_e reneg_spec__e,
  flea_ref_cu8_t*               allowed_ecc_curves_ref__prcu8,
  flea_ref_cu8_t*               allowed_sig_algs_ref__prcu8,
  flea_tls_flag_e               flags
);

flea_err_t THR_flea_tls_ctx_t__ctor_server(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_rw_stream_t*             rw_stream__pt,
  flea_ref_cu8_t*               cert_chain__pt,
  flea_al_u8_t                  cert_chain_len__alu8,
  const flea_cert_store_t*      trust_store__t,
  flea_ref_cu8_t*               server_key__pt,
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

flea_err_t THR_flea_tls_ctx_t__read_app_data(
  flea_tls_ctx_t*         tls_ctx_t,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
);

flea_err_t THR_flea_tls_ctx_t__send_app_data(
  flea_tls_ctx_t*  tls_ctx,
  const flea_u8_t* data,
  flea_u8_t        data_len
);

flea_err_t THR_flea_tls_ctx_t__flush_write_app_data(flea_tls_ctx_t* tls_ctx);


flea_err_t THR_flea_tls_ctx_t__renegotiate(
  flea_tls_ctx_t*          tls_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  /* new session id? */
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  flea_rev_chk_mode_e      rev_chk_mode__e,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
);

# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_TLS

#endif /* h-guard */
