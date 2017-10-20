#ifndef _flea_tls_int__H_
#define _flea_tls_int__H_

#include "internal/common/algo_len_int.h"
#include "flea/byte_vec.h"
#include "flea/pubkey.h"
#include "flea/privkey.h"
#include "internal/common/tls_rec_prot.h"
#include "internal/common/tls/tls_common.h"
#include "flea/tls_session_mngr.h"
#include "flea/cert_store.h"
#include "internal/common/tls/tls_ctx_fwd.h"
#include "flea/tls_session_mngr.h"


#ifdef __cplusplus
extern "C" {
#endif


#define FLEA_TLS_CERT_TYPE_RSA_SIGN   1
#define FLEA_TLS_CERT_TYPE_ECDSA_SIGN 64

#define FLEA_TLS_HELLO_RANDOM_SIZE    32
#define FLEA_TLS_MASTER_SECRET_SIZE   48

// maximum size that we will ever allocate to temporary store the cipher suites
#define FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE_HEAP 1024

#define FLEA_CONST_TLS_GCM_RECORD_IV_LEN       8
#define FLEA_CONST_TLS_GCM_FIXED_IV_LEN        4
#define FLEA_CONST_TLS_GCM_TAG_LEN             16


#define FLEA_TLS_MAX_MAC_SIZE     FLEA_MAC_MAX_OUTPUT_LENGTH      // (512 / 8)
#define FLEA_TLS_MAX_MAC_KEY_SIZE __FLEA_COMPUTED_MAC_MAX_KEY_LEN // 32
#define FLEA_TLS_MAX_IV_SIZE      FLEA_MAX(FLEA_CIPHER_MAX_BLOCK_LEN, FLEA_CONST_TLS_GCM_RECORD_IV_LEN)

/* fwd declaration */


typedef enum { PRF_LABEL_TEST, PRF_LABEL_CLIENT_FINISHED, PRF_LABEL_SERVER_FINISHED, PRF_LABEL_MASTER_SECRET,
               PRF_LABEL_KEY_EXPANSION } PRFLabel;

typedef struct
{
  flea_hash_id_t      hash_id__t;
  flea_pk_scheme_id_t pk_scheme_id__t;
} flea_tls__hash_sig_t;


struct struct_flea_tls_ctx_t
{
  flea_tls__connection_end_t connection_end; /* Server or Client */
#ifdef FLEA_USE_STACK_BUF
  flea_u8_t                  master_secret__bu8[FLEA_TLS_MASTER_SECRET_SIZE]; /* symmetric keys are derived from this */
#else
  flea_u8_t*                 master_secret__bu8;
#endif

  /* Pool of ciphersuites that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  const flea_ref_cu16_t*       allowed_cipher_suites__prcu16;
  flea_u16_t                   selected_cipher_suite__u16;

  /* max. supported TLS version */
  flea_tls__protocol_version_t version;

  /* stores hash function to use for the PRF algorithm */
  flea_hash_id_t               prf_hash_id__t;

  /* hash and sig algorithms used for KEX */
  flea_tls__hash_sig_t         kex_hash_sig__t;

  flea_rw_stream_t*            rw_stream__pt;
  flea_tls_rec_prot_t          rec_prot__t;
  const flea_cert_store_t*     trust_store__pt;
  flea_ref_cu8_t*              cert_chain_mbn__pt;
  flea_u8_t                    cert_chain_len__u8;

  flea_private_key_t*          private_key__pt;
  //
  // => client_ctx:
  flea_tls_client_session_t*   client_session_mbn__pt;
  flea_private_key_t*          private_key_for_client_mbn__pt;
  flea_revoc_chk_cfg_t         rev_chk_cfg__t;
  flea_u8_t                    sec_reneg_flag__u8;

#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t*                   own_vfy_data__bu8;
  flea_u8_t*                   peer_vfy_data__bu8;
#else
  flea_u8_t                    own_vfy_data__bu8[12];
  flea_u8_t                    peer_vfy_data__bu8[12];
#endif
  // TODO: into server
  flea_tls_session_mngr_t*     session_mngr_mbn__pt;
  flea_tls_session_entry_t*    server_active_sess_mbn__pt;
  flea_u8_t                    server_resume_session__u8;
  flea_u8_t                    allow_reneg__u8;
  flea_u8_t                    allow_insec_reneg__u8;
  flea_u8_t                    extension_ctrl__u8;       /* used only by server */
  flea_ref_cu8_t               allowed_ecc_curves__rcu8; /* by flea_ec_dom_par_id_t */
  flea_u8_t                    chosen_ecc_dp_internal_id__u8;

  // chosen hash algorithm in sig_alg extension. Signature algorithm is fixed by
  // the loaded certificate
  flea_ref_cu8_t allowed_sig_algs__rcu8;
  flea_hash_id_t chosen_hash_algorithm__t; // use as hash alg when signing with private key (server and client)
  flea_bool_t    can_use_ecdhe;            // true if sig alg extension produces a match so we can sign the ECDHE params
  // flea_stream_read_mode_e    handshake_read_mode__e;
  // flea_tls_flag_e flags;
  // TODO: MAKE UNION WITH CLIENT PRIVATE KEY:
};

struct struct_flea_tls_handshake_ctx_t
{
  /* only used by tls_client: */
  flea_public_key_t* ecdhe_pub_key__pt;

  flea_byte_vec_t*   client_and_server_random__pt;
  flea_tls_ctx_t*    tls_ctx__pt;
};

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
