/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_common__H_
#define _flea_tls_common__H_

#include "internal/common/tls/tls_cert_path.h"

#ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
extern "C" {
# endif


# define NO_COMPRESSION 0


flea_err_t THR_flea_tls__read_certificate(
  flea_tls_ctx_t*                    tls_ctx,
  flea_tls_handsh_reader_t*          hs_rdr__pt,
  flea_public_key_t*                 pubkey,
  flea_tls_cert_path_params_t const* cert_path_params__pct
);

flea_err_t THR_flea_tls__send_certificate(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx,
  flea_ref_cu8_t*  cert_chain__pt,
  flea_u8_t        cert_chain_len__u8
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
  // TODO: REDUCE RAM SIZE
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
# ifdef __cplusplus
}
# endif
# define FLEA_TLS_SEC_RENEG_FINISHED_SIZE 12
flea_err_t THR_flea_tls__send_change_cipher_spec(
  flea_tls_ctx_t* tls_ctx
);

flea_err_t THR_flea_tls__send_finished(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
);

flea_err_t THR_flea_tls_ctx_t__construction_helper(
  flea_tls_ctx_t*   ctx,
  flea_rw_stream_t* rw_stream__pt

  /*  const flea_u8_t*  session_id,
   * flea_al_u8_t      session_id_len*/
);

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state);

flea_err_t THR_flea_tls__create_master_secret(
  const flea_u8_t*            client_and_server_random,
  // const flea_u8_t * server_hello_random,
  // flea_u8_t* pre_master_secret,
  flea_byte_vec_t*            premaster_secret__pt,
  flea_u8_t*                  master_secret_res,
  flea_tls__cipher_suite_id_t ciph_id__e
);


/*flea_err_t THR_flea_tls__generate_key_block(
 * const flea_tls_ctx_t* tls_ctx,
 * // const flea_tls__security_parameters_t* security_parameters__pt,
 * flea_u8_t*            key_block,
 * flea_al_u8_t          key_block_len__alu8
 * );*/
flea_err_t THR_flea_tls__generate_key_block(
  // const flea_tls_ctx_t* tls_ctx,
  flea_al_u16_t                          selected_cipher_suite__alu16,
  const flea_tls__security_parameters_t* security_parameters__pt,
  flea_u8_t*                             key_block,
  flea_al_u8_t                           key_block_len__alu8
);

/**
 * Takes care of alert sending based on the type of error that occured. Throws
 * an error if the TLS session is terminated due to the error.
 */
flea_err_t THR_flea_tls__handle_tls_error(
  flea_tls_ctx_t* tls_ctx__pt,
  // flea_tls_rec_prot_t* rec_prot__pt,
  flea_err_t      err__t
  //  flea_tls_session_data_t * session_mbn__pt
);

flea_err_t THR_flea_tls__server_handshake(
  flea_tls_ctx_t* tls_ctx,
  flea_bool_t     is_reneg__b
);

flea_err_t THR_flea_tls__client_handshake(
  flea_tls_ctx_t*            tls_ctx,
  flea_bool_t                is_reneg__b,
  flea_tls_client_session_t* session_mbn__pt
);

/**
 * send a positive iteger big endian encoded as part of a handshake message.
 */
flea_err_t THR_flea_tls__send_handshake_message_int_be(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  flea_u32_t           int__u32,
  flea_al_u8_t         int_byte_width__alu8
);

flea_err_t THR_flea_tls_ctx_t__client_parse_extensions(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt
);

flea_al_u16_t flea_tls_ctx_t__compute_extensions_length(flea_tls_ctx_t* tls_ctx__pt);

flea_err_t THR_flea_tls_ctx_t__send_extensions_length(
  flea_tls_ctx_t*  tls_ctx__pt,
  flea_hash_ctx_t* hash_ctx_mbn__pt
);

flea_err_t THR_flea_tls_ctx_t__send_reneg_ext(
  flea_tls_ctx_t*  tls_ctx__pt,
  flea_hash_ctx_t* hash_ctx__pt
);

flea_bool_t flea_tls_ctx_t__do_send_sec_reneg_ext(flea_tls_ctx_t* tls_ctx__pt);

void flea_tls_set_tls_random(flea_tls_ctx_t* ctx__pt);

#endif // ifdef FLEA_HAVE_TLS
#endif /* h-guard */
