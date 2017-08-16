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
// TODO: cleaner solution?
# define FLEA_TLS_MAX_MAC_SIZE     (384 / 8)
# define FLEA_TLS_MAX_MAC_KEY_SIZE 32
# define FLEA_TLS_MAX_IV_SIZE      32
// #define FLEA_TLS_MAX_RECORD_DATA_SIZE 16384 // 2^14 max record sizeof
# define FLEA_TLS_MAX_PADDING_SIZE 255 // each byte must hold the padding value => 255 is max

// TODO: split up secure_reneg into ..._cert_fixed, cert_variable
typedef enum
{
  flea_tls_no_reneg,
  flea_tls_only_secure_reneg,
  flea_tls_allow_insecure_reneg
} flea_tls_renegotiation_spec_e;

typedef enum { flea_rev_chk_all, flea_rev_chk_none, flea_rev_chk_only_ee  } flea_rev_chk_mode_e;

typedef struct
{
  flea_rev_chk_mode_e    rev_chk_mode__e;
  const flea_byte_vec_t* crl_der__pt;
  flea_u16_t             nb_crls__u16;
} flea_revoc_chk_cfg_t;

// TODO: ASSIGN FIXED VALUES?
typedef enum { PRF_LABEL_TEST, PRF_LABEL_CLIENT_FINISHED, PRF_LABEL_SERVER_FINISHED, PRF_LABEL_MASTER_SECRET,
               PRF_LABEL_KEY_EXPANSION } PRFLabel;

typedef enum
{
  HANDSHAKE_TYPE_HELLO_REQUEST       = 0,
  HANDSHAKE_TYPE_CLIENT_HELLO        = 1,
  HANDSHAKE_TYPE_SERVER_HELLO        = 2,
  HANDSHAKE_TYPE_NEW_SESSION_TICKET  = 4,
  HANDSHAKE_TYPE_CERTIFICATE         = 11,
  HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
  HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
  HANDSHAKE_TYPE_SERVER_HELLO_DONE   = 14,
  HANDSHAKE_TYPE_CERTIFICATE_VERIFY  = 15,
  HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
  HANDSHAKE_TYPE_FINISHED            = 20
} HandshakeType;

typedef struct
{
  RecordType                   record_type;
  ContentType                  content_type;
  flea_tls__protocol_version_t version;
  flea_u16_t                   length;
  flea_u8_t*                   data;
} Record;

/*typedef struct
 * {
 * //flea_u8_t gmt_unix_time[4];
 * flea_u8_t random_bytes[32];
 * } Random;*/


// TODO: Extensions

typedef struct
{
  HandshakeType type;
  flea_u32_t    length; // actually 24 Bit type !!
  flea_u8_t*    data;
} HandshakeMessage;

typedef enum                 // dhe_dss, dhe_rsa, dh_anon,
{ KEY_EXCHANGE_ALGORITHM_RSA // ,
  // dh_dss, dh_rsa
} KeyExchangeAlgorithm;

typedef struct
{
  KeyExchangeAlgorithm algorithm;

  flea_u8_t            premaster_secret[256]; /* TODO: variable */
  flea_u8_t*           encrypted_premaster_secret;
  flea_u16_t           encrypted_premaster_secret_length;
  flea_u8_t*           ClientDiffieHellmanPublic;
} flea_tls__client_key_ex_t;

typedef enum { CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC = 1 } CHANGE_CIPHER_SPEC_TYPE;

typedef struct
{
  CHANGE_CIPHER_SPEC_TYPE change_cipher_spec;
} ChangeCipherSpec;

/*typedef struct
 * {
 * flea_u8_t  *verify_data;
 * flea_u32_t verify_data_length; // 12 for all cipher suites defined in TLS 1.2 - RFC 5246. is 24 bit!!
 * } flea_tls__finished_t;
 */

/**
 * ServerHelloDone: no content, no struct needed
 */

typedef enum
{
  FLEA_TLS_HMAC_SHA1,
  FLEA_TLS_HMAC_SHA256
} flea_tls__mac_algorithm_t;

typedef enum
{
  FLEA_TLS_BCA_AES,
  FLEA_TLS_BCA_TRIPLE_DES,
  FLEA_TLS_BCA_NULL
} flea_tls__bulk_cipher_alg_t;

typedef enum
{
  FLEA_TLS_CIPHER_TYPE_STREAM,
  FLEA_TLS_CIPHER_TYPE_BLOCK,
  FLEA_TLS_CIPHER_TYPE_AEAD
} flea_tls__cipher_type_t;

typedef struct
{
  flea_tls__connection_end_t connection_end; /* Server or Client */


  /*flea_u8_t mac_length;
   * flea_u8_t mac_key_length;*/
  // CompressionMethod *compression_methods; /* Pool of compression methods that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  // flea_u32_t        compression_methods_len;
  // TODO: MAKE ABSTRACT BUFS:
  flea_u8_t master_secret[48];                                         /* symmetric keys are derived from this */
  flea_u8_t client_and_server_random [2 * FLEA_TLS_HELLO_RANDOM_SIZE]; /* random value that the client sends */
  // flea_u8_t server_random [32];     /* random value that the server sends */
} flea_tls__security_parameters_t;

/*typedef struct
 * {
 * flea_u8_t* record_hdr__pu8;
 * flea_u8_t* message__pu8;
 * flea_u16_t message_len__u16;
 * flea_u16_t allocated_message_len__u16;
 * } flea_tls_record_t;
 */

# define flea_tls_record_t__SET_BUF(__p, __buf, __buf_len) \
  do {(__p)->record_hdr__pu8  = (__buf); \
      (__p)->message__pu8     = (__buf) + 5; \
      (__p)->message_len__u16 = 0; \
      (__p)->allocated_message_len__u16 = (__buf_len) - 5; \
  } while(0)


typedef struct
{
  flea_hash_id_t      hash_id__t;
  flea_pk_scheme_id_t pk_scheme_id__t;
} flea_tls__hash_sig_t;

typedef struct
{
  /* Security Parameters negotiated during handshake */
  flea_tls__security_parameters_t security_parameters; // can be deleted from memory (or saved for later resumption?) TODO: check again how it works, maybe only store master secret


  /*
   * Other information or configuration
   */

  // define 4 parameters independently instead of list of cipher suites
  const flea_ref_cu16_t*       allowed_cipher_suites__prcu16; /* Pool of ciphersuites that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  // flea_u8_t                    allowed_cipher_suites_len__u8;
  flea_u16_t                   selected_cipher_suite__u16; // TODO: change to cipher suite id type (already being used as such)

  flea_public_key_t            peer_pubkey; /* public key of peer */

  flea_tls__protocol_version_t version; /* max. supported TLS version */

# if 0
  flea_u8_t                    session_id[32]; /* Session ID for later resumption */
  flea_u8_t                    session_id_len;
# endif

  flea_hash_id_t               prf_hash_id__t; // stores hash function to use for the PRF algorithm

  flea_tls__hash_sig_t         cert_vfy_hash_sig__t; // hash and sig algorithms used for cert verify message
  flea_tls__hash_sig_t         kex_hash_sig__t;      // hash and sig algorithms used for KEX
  // TODO: could probably do a union for cert_vfy and kex

  // flea_byte_vec_t              premaster_secret__t; // shall be deleted after master_Secret is calculated

  /*#ifdef FLEA_USE_STACK_BUF
   * flea_u8_t                   premaster_secret__au8[256];
   #endif*/
  // flea_bool_t                    resumption;
  // TODO: ABSTRACT BUFF, AND NOT IN CTX (?):
  flea_u8_t                      key_block[128]; // size for key block for aes256+sha256 - max size for all ciphersuites in RFC

  flea_rw_stream_t*              rw_stream__pt;
  flea_tls_rec_prot_t            rec_prot__t;
  const flea_cert_store_t*       trust_store__pt;

  flea_hostn_validation_params_t hostn_valid_params__t;

  flea_ref_cu8_t*                cert_chain__pt;
  flea_u8_t                      cert_chain_len__u8;

  // TODO: SERVER SHOULD ONLY KEEP THE INSTANTIATED KEY OBJECT
  flea_ref_cu8_t*                private_key__pt;
  flea_private_key_t             private_key__t;

  flea_revoc_chk_cfg_t           rev_chk_cfg__t;
  flea_u8_t                      sec_reneg_flag__u8;
  // flea_u8_t                      client_has_sec_reneg__u8;

  flea_private_key_t             ecdhe_priv_key__t; // server needs to store it until the client sends his pubkey
  flea_public_key_t              ecdhe_pub_key__t;  // client needs to store it to send it afterwards


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
  flea_hash_id_t chosen_hash_algorithm__t;
  flea_bool_t    can_use_ecdhe;
  // flea_stream_read_mode_e    handshake_read_mode__e;
  // flea_tls_flag_e flags;
} flea_tls_ctx_t;


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
  flea_ref_cu8_t*               cert_chain__pt,
  flea_al_u8_t                  cert_chain_len__alu8,
  flea_ref_cu8_t*               client_public_key__pt,
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
  flea_ref_cu8_t*          private_key__pt,
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
