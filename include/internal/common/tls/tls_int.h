/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_int__H_
# define _flea_tls_int__H_

# include "internal/common/algo_len_int.h"
# include "flea/byte_vec.h"
# include "flea/pubkey.h"
# include "flea/privkey.h"
# include "internal/common/tls/tls_rec_prot.h"
# include "internal/common/tls/tls_common.h"
# include "internal/common/tls/tls_session_int_fwd.h"
# include "flea/cert_store.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "internal/common/tls/tls_const.h"
# include "flea/tls_fwd.h"
# include "flea/tls_psk.h"

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_TLS
#  define flea_tls_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)

typedef struct
{
  flea_rev_chk_mode_e   rev_chk_mode__e;
  const flea_ref_cu8_t* crl_der__pt;
  flea_u16_t            nb_crls__u16;
} flea_revoc_chk_cfg_t;

typedef enum { PRF_LABEL_TEST, PRF_LABEL_CLIENT_FINISHED, PRF_LABEL_SERVER_FINISHED, PRF_LABEL_MASTER_SECRET,
               PRF_LABEL_KEY_EXPANSION } PRFLabel;

typedef struct
{
  flea_hash_id_e      hash_id__t;
  flea_pk_scheme_id_e pk_scheme_id__t;
} flea_tls__hash_sig_t;

struct struct_flea_tls_ctx_t
{
  flea_tls__connection_end_t connection_end; /* Server or Client */
  void*                      client_or_server_ctx__pv;
#  ifdef FLEA_STACK_MODE
  flea_u8_t                  master_secret__bu8[FLEA_TLS_MASTER_SECRET_SIZE]; /* symmetric keys are derived from this */
#  else
  flea_u8_t*                 master_secret__bu8;
#  endif

  /* Pool of cipher suites that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites__pe;
  flea_u16_t                        nb_allowed_cipher_suites__u16;
  flea_tls_cipher_suite_id_t        selected_cipher_suite__e;

  /* max. supported TLS version */
  flea_tls__protocol_version_t      version;

  /* stores hash function to use for the PRF algorithm */
  flea_hash_id_e                    prf_hash_id__t;

  /* hash and sig algorithms used for KEX */
  flea_tls__hash_sig_t              kex_hash_sig__t;

  flea_rw_stream_t*                 rw_stream__pt;
  flea_recprot_t                    rec_prot__t;
  const flea_cert_store_t*          trust_store_mbn_for_server__pt;
  const flea_ref_cu8_t*             cert_chain_mbn__pt;
  flea_u8_t                         cert_chain_len__u8;

  flea_privkey_t*                   private_key__pt;
  flea_tls_clt_session_t*           client_session_mbn__pt;
  flea_privkey_t*                   private_key_for_client_mbn__pt;
  flea_revoc_chk_cfg_t              rev_chk_cfg__t;
  flea_u8_t                         sec_reneg_flag__u8;

#  ifdef FLEA_HAVE_TLS_CS_PSK
  flea_bool_t                       client_use_psk__b; // Only used by client. True if configured for PSK.
#  endif // ifdef FLEA_HAVE_TLS_CS_PSK

#  ifdef FLEA_HEAP_MODE
  flea_u8_t*                  own_vfy_data__bu8;
  flea_u8_t*                  peer_vfy_data__bu8;
#  else
  flea_u8_t                   own_vfy_data__bu8[12];
  flea_u8_t                   peer_vfy_data__bu8[12];
#  endif // ifdef FLEA_HEAP_MODE
  flea_u8_t                   allow_reneg__u8;
  flea_u8_t                   allow_insec_reneg__u8;
  flea_u8_t                   extension_ctrl__u8;        /* used only by server */
  const flea_ec_dom_par_id_e* allowed_ecc_curves__pe;
  flea_u16_t                  nb_allowed_curves__u16;
  flea_u8_t                   chosen_ecc_dp_internal_id__u8;
  const flea_tls_sigalg_e*    allowed_sig_algs__pe;
  flea_al_u16_t               nb_allowed_sig_algs__alu16;
  flea_hash_id_e              chosen_hash_algorithm__t;        // use as hash alg when signing with private key (server and client)
  flea_bool_t                 can_use_ecdhe;        // true if sig alg extension produces a match so we can sign the ECDHE params
  flea_tls_flag_e             cfg_flags__e;
#  ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
#   ifdef FLEA_STACK_MODE
  flea_u8_t                   peer_ee_cert__au8[FLEA_STKMD_X509_MAX_CERT_SIZE];
#   endif
  flea_byte_vec_t             peer_ee_cert_data__t;
  flea_x509_cert_ref_t        peer_ee_cert_ref__t;
#  endif // ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
#  ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
  flea_x509_cert_ref_t        peer_root_cert_ref__t;
  flea_u8_t                   peer_root_cert_set__u8;
#  endif
};

struct struct_flea_tls_handshake_ctx_t
{
  /* only used by tls_client: */
  flea_pubkey_t*   ecdhe_pub_key__pt;

  flea_byte_vec_t* client_and_server_random__pt;
  flea_tls_ctx_t*  tls_ctx__pt;
  flea_u8_t        silent_alarm__u8;
  flea_u8_t        is_reneg__b;
  flea_bool_t      is_sess_res__b;
};

#  define flea_tls_handshake_ctx_t__INIT(__p) \
  do {(__p)->silent_alarm__u8 = 0; memset((__p), 0, sizeof(*(__p))); \
  } while(0)

struct struct_flea_tls_srv_ctx_t
{
  flea_privkey_t*                private_key__pt;
  flea_tls_ctx_t                 tls_ctx__t;
  flea_tls_session_data_server_t active_session__t;
  flea_tls_session_mngr_t*       session_mngr_mbn__pt;
  flea_u8_t                      server_resume_session__u8;
  flea_u8_t                      server_session_id_assigned__u8;
  flea_u8_t                      max_fragm_len_code__u8;
#  ifdef FLEA_HAVE_TLS_CS_PSK
  flea_get_psk_cb_f              get_psk_mbn_cb__f;
  const void*                    psk_lookup_ctx_mbn__vp;
  const flea_u8_t*               identity_hint_mbn__pu8;
  flea_u16_t                     identity_hint_len__u16;
#  endif // ifdef FLEA_HAVE_TLS_CS_PSK
};


struct struct_flea_tls_clt_ctx_t
{
  flea_tls_ctx_t                  tls_ctx__t;
  flea_hostn_validation_params_t  hostn_valid_params__t;
#  ifdef FLEA_HAVE_TLS_CS_PSK
  flea_u8_t*                      psk__pu8;
  flea_u16_t                      psk_len__u16;
  flea_u8_t*                      identity__pu8;
  flea_u16_t                      identity_len__u16;
  flea_process_identity_hint_cb_f process_identity_hint_mbn_cb__f;
#  endif // ifdef FLEA_HAVE_TLS_CS_PSK
};

# endif // ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
}
# endif

#endif /* h-guard */
