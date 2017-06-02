/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "flea/cbc_filter.h"
#include "flea/hash_stream.h"
#include "flea/tee.h"
#include "flea/cert_store.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"
#include "internal/common/hash/parallel_hash.h"
#include "flea/rng.h"
#include <stdio.h>
#include "flea/pk_api.h"
#include "flea/pkcs8.h"

#ifdef FLEA_HAVE_TLS

flea_err_t THR_flea_tls__read_server_hello(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt
)
{
  flea_u8_t server_compression_meth__u8;
  flea_u8_t server_version_major_minor__au8[2];
  flea_u8_t session_id_len__u8;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u8_t ciphersuite__au8[2];

  // flea_u16_t cipher_suite_id__u16;

  FLEA_DECL_BUF(session_id__bu8, flea_u8_t, 32);
  const flea_al_u8_t max_session_id_len__alu8 = 32;
  FLEA_THR_BEG_FUNC();
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) < 41) /* min ServerHello length */
  {
    FLEA_THROW("length too small", FLEA_ERR_TLS_GENERIC);
  }
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  // keep track of length

  // read version

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      server_version_major_minor__au8,
      sizeof(server_version_major_minor__au8)
    )
  );
  if(server_version_major_minor__au8[0] != tls_ctx->version.major ||
    server_version_major_minor__au8[1] != tls_ctx->version.minor)
  {
    FLEA_THROW("version mismatch", FLEA_ERR_TLS_UNSUPP_PROT_VERSION);
  }
  // TODO: in this part the client has to decide if he accepts the server's TLS version - implement negotiation
  // read random
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      tls_ctx->security_parameters.server_random.gmt_unix_time,
      4
    )
  );

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      tls_ctx->security_parameters.server_random.random_bytes,
      28
    )
  );


  // read session id length
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &session_id_len__u8));
  // server_hello->session_id_length = handshake_msg->data[length++];
  // while(session_id_len__u8 > 0)
  if(session_id_len__u8 > max_session_id_len__alu8)
  {
    FLEA_THROW("invalid session id length", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  FLEA_ALLOC_BUF(session_id__bu8, session_id_len__u8);

  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, session_id__bu8, session_id_len__u8));
  // TODO: STORE SESSION ID

  // read cipher suites
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, ciphersuite__au8, sizeof(ciphersuite__au8)));

  tls_ctx->selected_cipher_suite__u16 = flea__decode_U16_BE(ciphersuite__au8);
  if(!flea_is_in_u16_list(tls_ctx->selected_cipher_suite__u16, tls_ctx->allowed_cipher_suites__prcu16))
  {
    FLEA_THROW("invalid ciphersuite selected by peer", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  /*tls_ctx->selected_cipher_suite__u16 = FLEA_TLS_RSA_WITH_AES_256_CBC_SHA;
   * tls_ctx->selected_cipher_suite__u16 = FLEA_TLS_RSA_WITH_AES_128_GCM_SHA256;*/
  // TODO: CHECK / SELECT CIPHERSUITE
  // - must be among presented ones in client hello => contained in allowed suites AND supported by compile config
  // read compression method
  // server_hello->compression_method = handshake_msg->data[length++];

  // server_compression_meth__u8 = handshake_msg->data[length++];

  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &server_compression_meth__u8));
  if(server_compression_meth__u8 != NO_COMPRESSION)
  {
    FLEA_THROW("unsupported compression method from server", FLEA_ERR_TLS_INV_ALGO_IN_SERVER_HELLO);
  }
  // TODO: parse extensions
  // for now simply ignore them

  // update security parameters

  // client wants to resume connection and has provided a session id
  if(tls_ctx->session_id_len != 0)
  {
    // TODO: IMPLEMENT "COMPARE IN STREAM" AND ELIMINATE LOCAL BUFFER
    if(0 == flea_memcmp_wsize(tls_ctx->session_id, tls_ctx->session_id_len, session_id__bu8, session_id_len__u8))
    {
      tls_ctx->resumption = FLEA_TRUE;
    }
  }
  // TODO: USE REF AND CPREF
  memcpy(tls_ctx->session_id, session_id__bu8, session_id_len__u8);
  tls_ctx->session_id_len = session_id_len__u8;

  // check length in the header field for integrity
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("Header length field mismatch", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(session_id__bu8);
  );
} /* THR_flea_tls__read_server_hello */

static flea_err_t THR_flea_tls__send_client_hello(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx
)
{
  flea_al_u16_t i;

  flea_u8_t null_byte[] = {0};
  flea_u32_t len        = 2 + 1 + 0 + 32 + 2 + 2 * tls_ctx->allowed_cipher_suites__prcu16->len__dtl + 1 + 1 + 0;

  FLEA_THR_BEG_FUNC();

  // calculate length for the header
  // TODO: include session id in the calculation (the 0 at 3rd place)
  // TODO: include extensions length (last place)

  // flea_u32_t len = 2 + 1 + 0 + 32 + 2 + tls_ctx->allowed_cipher_suites_len__u8 + 1 + 1 + 0;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CLIENT_HELLO,
      len
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      &tls_ctx->version.major,
      1
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      &tls_ctx->version.minor,
      1
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      tls_ctx->security_parameters.client_random.gmt_unix_time,
      sizeof(tls_ctx->security_parameters.client_random.gmt_unix_time)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      tls_ctx->security_parameters.client_random.random_bytes,
      sizeof(tls_ctx->security_parameters.client_random.random_bytes)
    )
  );

  // session ID empty => no resumption (new handshake negotiation)
  // TODO: include possibility to resume a session
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, null_byte, 1));

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_int_be(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      2 * tls_ctx->allowed_cipher_suites__prcu16->len__dtl,
      2
    )
  );

  for(i = 0; i < tls_ctx->allowed_cipher_suites__prcu16->len__dtl; i++)
  {
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_int_be(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        tls_ctx->allowed_cipher_suites__prcu16->data__pcu16[i],
        2
      )
    );
  }

  // compression methods: we don't support compression
  flea_u8_t one_byte[] = {1};
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, one_byte, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, null_byte, 1));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_client_hello */

static flea_err_t THR_flea_tls__read_cert_request(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;

  FLEA_DECL_BUF(cert_types__bu8, flea_u8_t, 7);         // TODO: define 7 somewhere? (7: number of different cert_types in RFC)
  FLEA_DECL_BUF(sig_algs__bu8, flea_u8_t, 32);          // TODO same as above + find a reasonable number of bytes
  FLEA_DECL_BUF(cert_authorities__bu8, flea_u8_t, 512); // TODO same as above
  flea_u8_t cert_types_len__u8;
  flea_u8_t sig_algs_len_to_dec__au8[2];
  flea_u16_t sig_algs_len__u16;
  flea_u8_t cert_authorities_len_to_dec__au8[2];
  flea_u16_t cert_authorities_len__u16;

  FLEA_THR_BEG_FUNC();
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  // read certificate types field
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &cert_types_len__u8));
  // TODO(FS): prevent overflow of stack buffer:
  FLEA_ALLOC_BUF(cert_types__bu8, cert_types_len__u8);
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, cert_types__bu8, cert_types_len__u8));

  // read signature algorithms field
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, sig_algs_len_to_dec__au8, 2));
  sig_algs_len__u16 = flea__decode_U16_BE(sig_algs_len_to_dec__au8);
  // TODO(FS): prevent overflow of stack buffer:
  FLEA_ALLOC_BUF(sig_algs__bu8, sig_algs_len__u16);
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, sig_algs__bu8, sig_algs_len__u16));

  // read certificate authorities field
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, cert_authorities_len_to_dec__au8, 2));
  cert_authorities_len__u16 = flea__decode_U16_BE(cert_authorities_len_to_dec__au8);
  // TODO(FS): prevent overflow of stack buffer:
  FLEA_ALLOC_BUF(cert_authorities__bu8, cert_authorities_len__u16);
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, cert_authorities__bu8, cert_authorities_len__u16));

  // check that there are no byes left
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("trailing bytes in certificate request message", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  // TODO: use / store values somehow !! (choose sig/hash algs, choose root out
  // of cert_authorities)
  tls_ctx__pt->cert_vfy_hash_id__t = flea_sha256; // TODO123: not hard coded

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(cert_types__bu8);
    FLEA_FREE_BUF_FINAL(sig_algs__bu8);
    FLEA_FREE_BUF_FINAL(cert_authorities__bu8);
  );
} /* THR_flea_tls__read_cert_request */

static flea_err_t THR_flea_tls__send_client_key_exchange_rsa(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_public_key_t*            pubkey,
  flea_byte_vec_t*              premaster_secret__pt
)
{
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(encrypted__t, FLEA_RSA_MAX_MOD_BYTE_LEN);
  FLEA_THR_BEG_FUNC();

  const flea_u32_t premaster_secret_len = 48;
  // first 2 bytes are version, following 46 random

  /*tls_ctx->premaster_secret[0] = tls_ctx->version.major;
   *  tls_ctx->premaster_secret[1] = tls_ctx->version.minor;*/
  FLEA_CCALL(THR_flea_byte_vec_t__resize(premaster_secret__pt, premaster_secret_len));
  premaster_secret__pt->data__pu8[0] = tls_ctx->version.major;
  premaster_secret__pt->data__pu8[1] = tls_ctx->version.minor;

  // random 46 byte
  flea_rng__randomize(premaster_secret__pt->data__pu8 + 2, premaster_secret_len - 2);

  /**
   *   RSA encryption is done using the RSAES-PKCS1-v1_5 encryption scheme
   *   https://tools.ietf.org/html/rfc3447#section-7.2
   */

  // pubkey->key_bit_size__u16
  // TODO: local abstract buf dependent on key size
  // flea_al_u16_t result_len = (pubkey->key_bit_size__u16 + 7) / 8;
  // flea_u8_t enc[256];
  FLEA_CCALL(
    THR_flea_public_key_t__encrypt_message(
      pubkey,
      flea_rsa_pkcs1_v1_5_encr,
      0,
      premaster_secret__pt->data__pu8,
      // tls_ctx->premaster_secret,
      premaster_secret_len,
      &encrypted__t

      /*enc,
       * &result_len*/
    )
  );

  flea_u8_t len_enc[2];
  flea__encode_U16_BE(encrypted__t.len__dtl, len_enc);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      encrypted__t.len__dtl + sizeof(len_enc)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      len_enc,
      sizeof(len_enc)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      encrypted__t.data__pu8,
      encrypted__t.len__dtl
    )
  );

  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&encrypted__t);
  );
} /* THR_flea_tls__send_client_key_exchange_rsa */

// send_client_key_exchange
static flea_err_t THR_flea_tls__send_client_key_exchange(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_public_key_t*            pubkey,
  flea_byte_vec_t*              premaster_secret__pt
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls__send_client_key_exchange_rsa(tls_ctx, p_hash_ctx, pubkey, premaster_secret__pt));

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls__send_cert_verify(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_ref_cu8_t*               client_key__pt
)
{
  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, 64); // MAX_HASH_SIZE parameter?
  FLEA_DECL_OBJ(key__t, flea_private_key_t);
  flea_u8_t hash_alg = 4; // sha256 // TODO:
  flea_u8_t sig_alg  = 1; // rsa    // make generic / derive from cert (?)
  flea_u32_t hdr_len__u32;
  flea_u8_t sig_len_enc__u8[2];
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(message_vec__t, 32); // TODO
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(sig_vec__t, 256);    // TODO
  flea_u8_t hash_len__u8;

  FLEA_THR_BEG_FUNC();

  hash_len__u8 = flea_hash__get_output_length_by_id(tls_ctx->cert_vfy_hash_id__t);
  FLEA_ALLOC_BUF(messages_hash__bu8, hash_len__u8); // TODO: determine size of hash function that is used

  FLEA_CCALL(
    THR_flea_tls_parallel_hash_ctx__final(
      p_hash_ctx,
      tls_ctx->cert_vfy_hash_id__t,
      FLEA_TRUE,
      messages_hash__bu8
    )
  );

  // read client key
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&key__t, client_key__pt->data__pcu8, client_key__pt->len__dtl));


  // digitally sign the messages hash
  FLEA_CCALL(
    THR_flea_byte_vec_t__set_content(
      &message_vec__t,
      messages_hash__bu8,
      hash_len__u8
    )
  );

  FLEA_CCALL(
    THR_flea_pk_api__sign_digest(
      messages_hash__bu8,
      hash_len__u8,
      flea_sha256,
      flea_rsa_pkcs1_v1_5_sign,
      &key__t,
      &sig_vec__t
    )
  );

  // send handshake message
  // calculate length to be used for the header first
  hdr_len__u32 = 2 + 2 + sig_vec__t.len__dtl; // sig/hash alg bytes + sig len bytes + sig

  // send header
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
      hdr_len__u32
    )
  );

  // send signature and hash algorithm bytes
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, &hash_alg, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, &sig_alg, 1));

  // send signature length
  flea__encode_U16_BE(sig_vec__t.len__dtl, sig_len_enc__u8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      sig_len_enc__u8,
      sizeof(sig_len_enc__u8)
    )
  );

  // send signature
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      sig_vec__t.data__pu8,
      sig_vec__t.len__dtl
    )
  );

  FLEA_THR_FIN_SEC(
    flea_private_key_t__dtor(&key__t);
    FLEA_FREE_BUF_FINAL(messages_hash__bu8);
    flea_byte_vec_t__dtor(&message_vec__t);
    flea_byte_vec_t__dtor(&sig_vec__t);
  );
} /* THR_flea_tls__send_cert_verify */

static flea_err_t THR_flea_handle_handsh_msg(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls__handshake_state_t*  handshake_state,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt

)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  FLEA_DECL_OBJ(hash_ctx_copy__t, flea_hash_ctx_t);
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx->rec_prot__t));
  if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) != HANDSHAKE_TYPE_FINISHED)
  {
    FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, p_hash_ctx__pt));
  }
  // TODO: WHY COMPARISON WITH '==' ?
  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_HELLO)
    {
      FLEA_CCALL(THR_flea_tls__read_server_hello(tls_ctx, &handsh_rdr__t));
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE
        | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
 // | FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST // only enable this
 // after the server sent his certificate because only authenticated
 // servers can ask for client authentication
        | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE &&
    flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE)
  {
    // TODO: DETERMINE KEX TYPE DYNAMICALLY:
    flea_tls_cert_path_params_t cert_path_params__t =
    {.kex_type__e                  = flea_tls_kex__rsa, .client_cert_type__e = 0,
     .validate_server_or_client__e = FLEA_TLS_SERVER,
     .hostn_valid_params__pt       = &tls_ctx->hostn_valid_params__t};
    FLEA_CCALL(
      THR_flea_tls__read_certificate(
        tls_ctx,
        &handsh_rdr__t,
        &tls_ctx->peer_pubkey,
        &cert_path_params__t
      )
    );
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
      | FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
      | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE &&
    flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE)
  {
    // TODO: implement
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
      | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST &&
    flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE_REQUEST)
  {
    if(tls_ctx->cert_chain__pt == NULL)
    {
      FLEA_THROW("Server requested a certificate but client has none", FLEA_ERR_TLS_GENERIC);
    }

    FLEA_CCALL(THR_flea_tls__read_cert_request(tls_ctx, &handsh_rdr__t));
    handshake_state->send_client_cert  = FLEA_TRUE;
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_HELLO_DONE)
    {
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      if(flea_tls_handsh_reader_t__get_msg_rem_len(&handsh_rdr__t) != 0)
      {
        FLEA_THROW("invalid length of server hello done", FLEA_ERR_TLS_GENERIC);
      }
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }
  // TODO: WHY COMPARISON WITH '==' ?
  // ANSWER (jroth): Da es davor keine
  // optionalen Nachrichten gibt, muss eigentlich genau diese Nachricht und
  // keine andere erwartet werden, also '==' statt '&' bildet das genauer ab
  else if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
    {
      // TODO: actually we don't need a copy since this is the last message.
      // Alternatively implement a 'select' method to get the pointer to the appropriate
      // hash_ctx and use this
      FLEA_CCALL(THR_flea_tls_parallel_hash_ctx__copy(&hash_ctx_copy__t, p_hash_ctx__pt, flea_sha256));
      FLEA_CCALL(THR_flea_tls__read_finished(tls_ctx, &handsh_rdr__t, &hash_ctx_copy__t));

      handshake_state->finished = FLEA_TRUE;
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }
  else
  {
    FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
  }
  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&hash_ctx_copy__t);
    flea_tls_handsh_reader_t__dtor(&handsh_rdr__t);
  );
} /* THR_flea_handle_handsh_msg */

flea_err_t THR_flea_tls__client_handshake(flea_tls_ctx_t* tls_ctx)
{
  flea_tls__handshake_state_t handshake_state;

  FLEA_THR_BEG_FUNC();

  // define and init state
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_tls_parallel_hash_ctx_t p_hash_ctx;
# ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE;
# else
  flea_u8_t premaster_secret__au8[FLEA_RSA_MAX_MOD_BYTE_LEN];
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_EMPTY_ALLOCATABLE(
    premaster_secret__au8,
    sizeof(premaster_secret__au8)
    );
# endif
  flea_hash_id_t hash_ids[] = {flea_sha256}; // TODO123: not hardcoded!!!!!
  FLEA_CCALL(THR_flea_tls_parallel_hash_ctx__ctor(&p_hash_ctx, hash_ids, 1));
  while(1)
  {
    // initialize handshake by sending CLIENT_HELLO
    if(handshake_state.initialized == FLEA_FALSE)
    {
      // send client hello
      FLEA_CCALL(THR_flea_tls__send_client_hello(tls_ctx, &p_hash_ctx));
      handshake_state.initialized       = FLEA_TRUE;
      handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO;
    }

    /*
     *  1) read next Record
     *  2) if it's Alert: handle it
     *     if it's Handshake Message or Change Cipher Spec Message: process it if it's among the expected_messages
     */


    /*
     * read next record
     */
    if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_NONE)
    {
      // TODO: SUBFUNCTION WHICH HANDLES HANDSHAKE MESSAGES
      ContentType cont_type__e;
      FLEA_CCALL(THR_flea_tls_rec_prot_t__get_current_record_type(&tls_ctx->rec_prot__t, &cont_type__e));

      if(cont_type__e == CONTENT_TYPE_HANDSHAKE)
      {
        FLEA_CCALL(
          THR_flea_handle_handsh_msg(
            tls_ctx,
            &handshake_state,
            &p_hash_ctx
          )
        );
        if(handshake_state.finished == FLEA_TRUE)
        {
          break;
        }
        continue;
        //    TODO: CALL CTORS FOR ALL OBJECTS

        // update hash for all incoming handshake messages
        // TODO: only include messages sent AFTER ClientHello (and ClientHello). At the moment it could include HelloRequest received before sending HelloRequest

        // exclude finished message because we must not have it in our hash computation
      }
      else if(cont_type__e == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
        }
        else
        {
          flea_u8_t dummy_byte;
          flea_al_u16_t len_one__alu16 = 1;
          // TODO: verify correctness of the message (?)

          /*
           * Enable encryption for incoming messages
           */

          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__read_data(
              &tls_ctx->rec_prot__t,
              CONTENT_TYPE_CHANGE_CIPHER_SPEC,
              &dummy_byte,
              &len_one__alu16,
              flea_read_full
            )
          );

          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__set_ciphersuite(
              &tls_ctx->rec_prot__t,
              flea_tls_read,
              FLEA_TLS_CLIENT,
              tls_ctx->selected_cipher_suite__u16,
              tls_ctx->key_block
            )
          );
          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;

          continue;
        }
      }
      else if(cont_type__e == CONTENT_TYPE_ALERT)
      {
        // TODO: handle alert message properly,i.e. close connection
        FLEA_THROW("Received unhandled alert", FLEA_ERR_TLS_GENERIC);
      }
      else
      {
        // TODO: SEND ALERT, CLOSE CONNECTION
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
    // We don't expect another message so it's our turn to continue
    else // TODO: CONSIDER EXPLICIT MODELLING OF THIS CONDITION
    {
      flea_al_u8_t key_block_len__alu8;

      // if we have to send a certificate, send it now
      if(handshake_state.send_client_cert == FLEA_TRUE)
      {
        FLEA_CCALL(
          THR_flea_tls__send_certificate(
            tls_ctx,
            &p_hash_ctx,
            tls_ctx->cert_chain__pt,
            tls_ctx->cert_chain_len__u8
          )
        );
      }

      // TODO: INIT PUBKEY IN CTOR!
      FLEA_CCALL(
        THR_flea_tls__send_client_key_exchange(
          tls_ctx,
          &p_hash_ctx,
          &tls_ctx->peer_pubkey,
          &premaster_secret__t
        )
      );

      // send CertificateVerify message if we sent a certificate
      if(handshake_state.send_client_cert == FLEA_TRUE)
      {
        FLEA_CCALL(THR_flea_tls__send_cert_verify(tls_ctx, &p_hash_ctx, tls_ctx->private_key__pt));
      }

      // send change cipher spec (initiate encryption/authentication)
      FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx));

      /*
       * Enable encryption for outgoing messages
       */

      FLEA_CCALL(
        THR_flea_tls__create_master_secret(
          tls_ctx->security_parameters.client_random,
          tls_ctx->security_parameters.server_random,
          // tls_ctx->premaster_secret,
          &premaster_secret__t,
          tls_ctx->security_parameters.master_secret,
          tls_ctx->selected_cipher_suite__u16
        )
      );
      FLEA_CCALL(
        THR_flea_tls_get_key_block_len_from_cipher_suite_id(
          tls_ctx->selected_cipher_suite__u16,
          &key_block_len__alu8
        )
      );
      FLEA_CCALL(
        THR_flea_tls__generate_key_block(
          // &tls_ctx->security_parameters,
          tls_ctx,
          tls_ctx->key_block,
          key_block_len__alu8
        )
      );

      FLEA_CCALL(
        THR_flea_tls_rec_prot_t__set_ciphersuite(
          &tls_ctx->rec_prot__t,
          flea_tls_write,
          FLEA_TLS_CLIENT,
          tls_ctx->selected_cipher_suite__u16,
          tls_ctx->key_block
        )
      );


      FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &p_hash_ctx));

      handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
      continue;
    }
  }
  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&premaster_secret__t);
    THR_flea_tls_parallel_hash_ctx__dtor(&p_hash_ctx);
  );
} /* THR_flea_tls__client_handshake */

flea_err_t THR_flea_tls_ctx_t__ctor_client(
  flea_tls_ctx_t*          tls_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  const flea_ref_cu8_t*    server_name__pcrcu8,
  flea_host_id_type_e      host_name_id__e,
  flea_rw_stream_t*        rw_stream__pt,
  const flea_u8_t*         session_id__pcu8,
  flea_al_u8_t             session_id_len__alu8,
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  flea_ref_cu8_t*          client_private_key__pt,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  flea_rev_chk_mode_e      rev_chk_mode__e,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
)
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();
  tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e = rev_chk_mode__e;
  tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16    = nb_crls__alu16;
  tls_ctx__pt->rev_chk_cfg__t.crl_der__pt     = crl_der__pt;
  tls_ctx__pt->cert_chain__pt     = cert_chain__pt;
  tls_ctx__pt->cert_chain_len__u8 = cert_chain_len__alu8;
  tls_ctx__pt->private_key__pt    = client_private_key__pt;
  tls_ctx__pt->allowed_cipher_suites__prcu16 = allowed_cipher_suites__prcu16;

  if(server_name__pcrcu8)
  {
    tls_ctx__pt->hostn_valid_params__t.host_id__ct = *server_name__pcrcu8;
  }
  else
  {
    tls_ctx__pt->hostn_valid_params__t.host_id__ct.data__pcu8 = NULL;
    tls_ctx__pt->hostn_valid_params__t.host_id__ct.len__dtl   = 0;
  }
  // tls_ctx->hostn_valid_params__t.host_id__ct.len__dtl = strlen(server_name__cs);
  tls_ctx__pt->hostn_valid_params__t.host_id_type__e = host_name_id__e;

  tls_ctx__pt->trust_store__pt = trust_store__pt;

  FLEA_CCALL(
    THR_flea_tls_ctx_t__construction_helper(
      tls_ctx__pt,
      rw_stream__pt,
      session_id__pcu8,
      session_id_len__alu8
    )
  );
  err__t = THR_flea_tls__client_handshake(tls_ctx__pt);
  FLEA_CCALL(THR_flea_tls__handle_tls_error(&tls_ctx__pt->rec_prot__t, err__t));
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__ctor_client */

#endif /* ifdef FLEA_HAVE_TLS */
