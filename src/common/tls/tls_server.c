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
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"
#include "flea/rng.h"
#include <stdio.h>
#include "flea/pkcs8.h"
#include "flea/rsa.h"

flea_err_t THR_flea_tls__read_client_hello(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u8_t client_version_major_minor__au8[2];
  flea_u8_t session_id_len__u8;

  FLEA_DECL_BUF(session_id__bu8, flea_u8_t, 32);
  const flea_al_u8_t max_session_id_len__alu8 = 32;
  FLEA_DECL_BUF(cipher_suites__bu8, flea_u8_t, 128); // TODO: think about the max buffer size !
  flea_u16_t cipher_suites_len__u16;
  const flea_u16_t max_cipher_suites_len__alu16 = 128;
  flea_u8_t client_compression_methods_len__u8;
  FLEA_DECL_BUF(client_compression_methods__bu8, flea_u8_t, 32); // TODO: do we need more than 2, actually? check how many are defined (2 in the original TLS RFC, maybe more in other RFCs?)
  const flea_u8_t max_client_compression_methods_len__u8 = 32;
  flea_bool_t found_compression_method;
  FLEA_THR_BEG_FUNC();


  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) < 34)
  {
    FLEA_THROW("message too short", FLEA_ERR_TLS_GENERIC);
  }

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  // read version
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      client_version_major_minor__au8,
      sizeof(client_version_major_minor__au8)
    )
  );
  // TODO: negotiate version properly
  if(client_version_major_minor__au8[0] != tls_ctx->version.major ||
    client_version_major_minor__au8[1] != tls_ctx->version.minor)
  {
    FLEA_THROW("Version mismatch!", FLEA_ERR_TLS_GENERIC);
  }

  // read random
  // TODO: CHECK HOW TIME IS TO BE USED AND THEN ENCODE IT CORRECTLY
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      tls_ctx->security_parameters->client_random.gmt_unix_time,
      4
    )
  );
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      tls_ctx->security_parameters->client_random.random_bytes,
      28
    )
  );


  // read session id length
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &session_id_len__u8));
  if(session_id_len__u8 > max_session_id_len__alu8)
  {
    FLEA_THROW("invalid session id length", FLEA_ERR_TLS_GENERIC);
  }

  // read session id
  FLEA_ALLOC_BUF(session_id__bu8, session_id_len__u8);
  FLEA_CCALL(THR_flea_rw_stream_t__force_read(hs_rd_stream__pt, session_id__bu8, session_id_len__u8));
  // TODO: if != 0: resumption !

  // TODO: stream function to read in the length
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, ((flea_u8_t*) &cipher_suites_len__u16) + 1));
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, (flea_u8_t*) &cipher_suites_len__u16));
  if(cipher_suites_len__u16 > max_cipher_suites_len__alu16)
  {
    FLEA_THROW("implementation does not support the given cipher suites length", FLEA_ERR_TLS_GENERIC);
  }

  // read cipher suites
  FLEA_ALLOC_BUF(cipher_suites__bu8, cipher_suites_len__u16);
  FLEA_CCALL(THR_flea_rw_stream_t__force_read(hs_rd_stream__pt, cipher_suites__bu8, cipher_suites_len__u16));
  flea_bool_t found = FLEA_TRUE;
  // TODO: need to check if we support one of the client's cipher suite and we
  // need to choose one !! (hard coded RSA AES 256)
  if(found == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on cipher", FLEA_ERR_TLS_GENERIC);
  }

  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &client_compression_methods_len__u8));
  if(client_compression_methods_len__u8 > max_client_compression_methods_len__u8)
  {
    FLEA_THROW("implementation does not support the given compression methods length", FLEA_ERR_TLS_GENERIC);
  }
  FLEA_ALLOC_BUF(client_compression_methods__bu8, client_compression_methods_len__u8);
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      client_compression_methods__bu8,
      client_compression_methods_len__u8
    )
  );
  // we only support no compression
  found_compression_method = FLEA_FALSE;
  for(flea_u8_t i = 0; i < client_compression_methods_len__u8; i++)
  {
    if(client_compression_methods__bu8[i] == NO_COMPRESSION)
    {
      found_compression_method = FLEA_TRUE;
      break;
    }
  }
  if(found_compression_method == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on compression method", FLEA_ERR_TLS_GENERIC);
  }

  // TODO: parse extensions

  // check length in the header field for integrity
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("Header length field mismatch", FLEA_ERR_TLS_GENERIC);
  }


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(session_id__bu8);
    FLEA_FREE_BUF_FINAL(cipher_suites__bu8);
    FLEA_FREE_BUF_FINAL(client_compression_methods__bu8);
  );
} /* THR_flea_tls__read_client_hello */

static flea_err_t THR_flea_tls__send_server_hello(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
)
{
  FLEA_THR_BEG_FUNC();

  // calculate length for the header
  // TODO: include cipher suites length instead of hard coded 2 (5+6th place)
  // TODO: include extensions length (last place)
  // TODO: change 4th element (32) to the real SessionID length

  flea_u32_t len = 2 + 32 + 1 + 32 + 2 + 1;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      HANDSHAKE_TYPE_SERVER_HELLO,
      len
    )
  );

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &tls_ctx->version.major, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &tls_ctx->version.minor, 1));

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters->client_random.gmt_unix_time,
      sizeof(tls_ctx->security_parameters->client_random.gmt_unix_time)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters->client_random.random_bytes,
      sizeof(tls_ctx->security_parameters->client_random.random_bytes)
    )
  );

  // TODO: actual implementation, e.g. support renegotiation
  flea_u8_t dummy_session_id_len = 32;
  flea_u8_t dummy_session_id[32];
  flea_rng__randomize(dummy_session_id, dummy_session_id_len);


  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &dummy_session_id_len, 1));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      dummy_session_id,
      dummy_session_id_len
    )
  );

  // TODO: hard coded
  flea_u8_t suite[] = {0x00, 0x3d};
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, suite, 2));

  // We don't support compression
  flea_u8_t null_byte = 0;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &null_byte, 1));


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_server_hello */

static flea_err_t THR_flea_tls__send_certificate(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx,
  flea_ref_cu8_t*  cert_chain__pt,
  flea_u8_t        cert_chain_len__u8
)
{
  flea_u32_t hdr_len__u32;
  flea_u32_t cert_list_len__u32;

  FLEA_THR_BEG_FUNC();

  // TODO: enable option to exclude the root CA (RFC: MAY be ommited)

  // calculate length for the header
  hdr_len__u32 = 3; // 3 byte for length of certificate list
  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    hdr_len__u32 += 3; // 3 byte for length encoding of each certificate
    hdr_len__u32 += cert_chain__pt[i].len__dtl;
  }

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      HANDSHAKE_TYPE_CERTIFICATE,
      hdr_len__u32
    )
  );

  // encode length
  // TODO use stream function for encoding
  cert_list_len__u32 = hdr_len__u32 - 3;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      &((flea_u8_t*) &cert_list_len__u32)[2],
      1
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      &((flea_u8_t*) &cert_list_len__u32)[1],
      1
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      &((flea_u8_t*) &cert_list_len__u32)[0],
      1
    )
  );

  // TODO use stream function for encoding
  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        hash_ctx,
        &((flea_u8_t*) &(cert_chain__pt[i].len__dtl))[2],
        1
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        hash_ctx,
        &((flea_u8_t*) &(cert_chain__pt[i].len__dtl))[1],
        1
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        hash_ctx,
        &((flea_u8_t*) &(cert_chain__pt[i].len__dtl))[0],
        1
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        hash_ctx,
        cert_chain__pt[i].data__pcu8,
        cert_chain__pt[i].len__dtl
      )
    );
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_certificate */

static flea_err_t THR_flea_tls__read_client_key_exchange_rsa(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_ref_cu8_t*           server_key__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u16_t enc_premaster_secret_len__u16;
  flea_private_key_t key_t;
  const flea_u16_t max_enc_premaster_secret_len__u16 = 256;

  FLEA_DECL_BUF(enc_premaster_secret__bu8, flea_u8_t, 256); // TODO: need more ?
  FLEA_DECL_BUF(premaster_secret__bu8, flea_u8_t, 48);
  FLEA_THR_BEG_FUNC();

  // read server key

  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&key_t, server_key__pt->data__pcu8, server_key__pt->len__dtl));


  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  // read encrypted premaster secret length
  // TODO: stream function to read in the length
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, ((flea_u8_t*) &enc_premaster_secret_len__u16) + 1));
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, (flea_u8_t*) &enc_premaster_secret_len__u16));
  if(enc_premaster_secret_len__u16 > max_enc_premaster_secret_len__u16)
  {
    FLEA_THROW("encrypted premaster secret too long", FLEA_ERR_TLS_GENERIC);
  }

  // read encrypted premaster secret
  FLEA_ALLOC_BUF(enc_premaster_secret__bu8, enc_premaster_secret_len__u16);
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      enc_premaster_secret__bu8,
      enc_premaster_secret_len__u16
    )
  );

  // decrypt to 48 byte premaster secret


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_client_key_exchange_rsa */

static flea_err_t THR_flea_tls__read_client_key_exchange(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_ref_cu8_t*           server_key__pt
)
{
  FLEA_THR_BEG_FUNC();

  // TODO: choose appropriate function
  FLEA_CCALL(THR_flea_tls__read_client_key_exchange_rsa(tls_ctx, hs_rdr__pt, server_key__pt));

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_handle_handsh_msg(
  flea_tls_ctx_t*              tls_ctx,
  flea_tls__handshake_state_t* handshake_state,
  flea_hash_ctx_t*             hash_ctx__pt,
  flea_ref_cu8_t*              server_key__pt
)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx->rec_prot__t));
  if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) != HANDSHAKE_TYPE_FINISHED)
  {
    FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, hash_ctx__pt));
  }

  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CLIENT_HELLO)
    {
      FLEA_CCALL(THR_flea_tls__read_client_hello(tls_ctx, &handsh_rdr__t));
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      return FLEA_ERR_FINE;
    }
    else
    {
      FLEA_THROW("Unexpected message", FLEA_ERR_TLS_GENERIC);
    }
  }

  if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
  {
    handshake_state->expected_messages ^= FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE;
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE)
    {
      printf("SM: reading certificate\n");
      // TODO: read certificate and verify

      return FLEA_ERR_FINE;
    }
  }
  if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE)
  {
    handshake_state->expected_messages ^= FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE;
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE)
    {
      FLEA_CCALL(THR_flea_tls__read_client_key_exchange(tls_ctx, &handsh_rdr__t, server_key__pt));
      return FLEA_ERR_FINE;
    }
  }

  if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY)
  {
    handshake_state->expected_messages ^= FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY;
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
    {
      // TODO: read certificate verify
      return FLEA_ERR_FINE;
    }
  }

  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
    {
      // TODO: read finished
      return FLEA_ERR_FINE;
    }
    else
    {
      FLEA_THROW("Expected finished message, but got something else", FLEA_ERR_TLS_GENERIC);
    }
  }

  FLEA_THROW("No handshake message processed", FLEA_ERR_TLS_INVALID_STATE);

  FLEA_THR_FIN_SEC(
    flea_tls_handsh_reader_t__dtor(&handsh_rdr__t);
  );
} /* THR_flea_handle_handsh_msg */

flea_err_t THR_flea_tls__server_handshake(
  flea_tls_ctx_t*   tls_ctx,
  flea_rw_stream_t* rw_stream__pt,
  flea_ref_cu8_t*   cert_chain__pt,
  flea_u32_t        cert_chain_len__u32,
  flea_ref_cu8_t*   server_key__pt
)
{
  FLEA_THR_BEG_FUNC();

  // define and init state
  flea_tls__handshake_state_t handshake_state;
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_hash_ctx_t hash_ctx;
  THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256); // TODO: initialize properly

  // flea_public_key_t pubkey; // TODO: -> tls_ctx

  // received records and handshakes for processing the current state
  HandshakeMessage recv_handshake;

  // set to true and wait for hello_client
  handshake_state.initialized       = FLEA_TRUE;
  handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO;
  handshake_state.send_client_cert  = FLEA_FALSE; // TODO: implement client cert checking / certificate request

  while(handshake_state.finished != FLEA_TRUE)
  {
    /*
     * read next record
     */
    if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_NONE)
    {
      ContentType cont_type__e;
      FLEA_CCALL(THR_flea_tls_rec_prot_t__get_current_record_type(&tls_ctx->rec_prot__t, &cont_type__e));

      // TODO: record type argument has to be removed because it's determined by the current connection state in tls_ctx
      if(cont_type__e == CONTENT_TYPE_HANDSHAKE)
      {
        FLEA_CCALL(THR_flea_handle_handsh_msg(tls_ctx, &handshake_state, &hash_ctx, server_key__pt));
        // FLEA_CCALL(THR_flea_tls__read_handshake_message(tls_ctx, &recv_handshake, &hash_ctx));
      }
      else if(cont_type__e == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
        }
        else
        {
          /*
           * Enable encryption for incoming messages
           */
          // setup key material
          FLEA_CCALL(
            THR_flea_tls__create_master_secret(
              tls_ctx->security_parameters->client_random,
              tls_ctx->security_parameters->server_random,
              tls_ctx->premaster_secret,
              tls_ctx->security_parameters->master_secret
            )
          );
          FLEA_CCALL(THR_flea_tls__generate_key_block(tls_ctx, tls_ctx->key_block));

          // enable encryption for read direction
          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
              &tls_ctx->rec_prot__t,
              flea_tls_read,
              flea_aes256,
              flea_sha256,
              flea_hmac_sha256,
              tls_ctx->key_block + 2 * 32 + 32,               /* cipher_key__pcu8, "2*32" = 2*mac key size, "+ 32" = cipher_key_size */
              32,                                             /* cipher_key_len */
              tls_ctx->key_block + 32 /* 32 = mac_key_size*/, /* mac_key__pcu8 */
              32 /*mac_key_len */,
              32 /* mac_len */
            )
          );


          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;

          continue;
        }
      }
      else if(cont_type__e == CONTENT_TYPE_ALERT)
      {
        // TODO: handle alert message properly
        FLEA_THROW("Received unhandled alert", FLEA_ERR_TLS_GENERIC);
      }
      else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
    // We don't expect another message so it's our turn to continue
    else
    {
      if(handshake_state.sent_first_round == FLEA_FALSE)
      {
        FLEA_CCALL(THR_flea_tls__send_server_hello(tls_ctx, &hash_ctx));

        FLEA_CCALL(THR_flea_tls__send_certificate(tls_ctx, &hash_ctx, cert_chain__pt, cert_chain_len__u32));

        FLEA_CCALL(
          THR_flea_tls__send_handshake_message(
            &tls_ctx->rec_prot__t,
            &hash_ctx,
            HANDSHAKE_TYPE_SERVER_HELLO_DONE,
            (flea_u8_t*) NULL,
            0
          )
        );

        handshake_state.sent_first_round = FLEA_TRUE;

        // TODO: expect certificate (when requested)
        handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE;
      }
      else
      {
        // send change_cipher_spec
        printf("SM: switching on encryption on write...\n");
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
            &tls_ctx->rec_prot__t,
            flea_tls_write,
            flea_aes256,
            flea_sha256,
            flea_hmac_sha256,
            tls_ctx->key_block + 2 * 32, /* cipher_key__pcu8, 32 = mac key size*/
            32,                          /* cipher_key_len */
            tls_ctx->key_block,          /* mac_key__pcu8 */
            32 /*mac_key_len */,
            32 /* mac_len */
          )
        );


        // send finished
        printf("sent finished\n");

        handshake_state.finished = FLEA_TRUE;


        /*
         * Enable encryption for outgoing messages
         */
      }

      continue;
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__server_handshake */
