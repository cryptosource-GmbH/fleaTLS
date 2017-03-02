/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_common__H_
#define _flea_tls_common__H_

#ifdef __cplusplus
extern "C" {
#endif

#define NO_COMPRESSION 0

flea_err_t THR_flea_tls__read_certificate(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_public_key_t*        pubkey
);

flea_err_t THR_flea_tls__send_handshake_message_hdr(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  HandshakeType        type,
  flea_u32_t           content_len__u32
);

flea_err_t THR_flea_tls__send_handshake_message_content(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  const flea_u8_t*     msg_bytes,
  flea_u32_t           msg_bytes_len
);

flea_err_t THR_flea_tls__send_handshake_message(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  HandshakeType        type,
  const flea_u8_t*     msg_bytes,
  flea_u32_t           msg_bytes_len
);

flea_err_t THR_flea_tls__read_finished(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_hash_ctx_t*          hash_ctx
);

typedef struct
{
  flea_u16_t  expected_messages;
  flea_bool_t finished;
  flea_bool_t initialized;
  flea_bool_t send_client_cert;
  flea_bool_t sent_first_round; // only relevant for server
} flea_tls__handshake_state_t;

typedef enum
{
  FLEA_TLS_HANDSHAKE_EXPECT_NONE                = 0x0, // zero <=> client needs to send his "second round"
  FLEA_TLS_HANDSHAKE_EXPECT_HELLO_REQUEST       = 0x1,
  FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO        = 0x2,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO        = 0x4,
  FLEA_TLS_HANDSHAKE_EXPECT_NEW_SESSION_TICKET  = 0x8,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE         = 0x10,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE = 0x20,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST = 0x40,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE   = 0x80,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY  = 0x100,
  FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE = 0x200,
  FLEA_TLS_HANDSHAKE_EXPECT_FINISHED            = 0x400,
  FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC  = 0x800
} flea_tls__expect_handshake_type_t;
#ifdef __cplusplus
}
#endif

flea_err_t THR_flea_tls__send_change_cipher_spec(
  flea_tls_ctx_t* tls_ctx
);

flea_err_t THR_flea_tls__send_finished(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
);

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state);

flea_err_t THR_flea_tls__create_master_secret(
  Random           client_hello_random,
  Random           server_hello_random,
  // flea_u8_t* pre_master_secret,
  flea_byte_vec_t* premaster_secret__pt,
  flea_u8_t*       master_secret_res
);


flea_err_t THR_flea_tls__generate_key_block(
  flea_tls_ctx_t* tls_ctx,
  flea_u8_t*      key_block
);

#endif /* h-guard */
