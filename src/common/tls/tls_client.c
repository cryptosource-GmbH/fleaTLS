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
#include "flea/rng.h"
#include <stdio.h>


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
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      server_version_major_minor__au8,
      sizeof(server_version_major_minor__au8)
    )
  );
  if(server_version_major_minor__au8[0] != tls_ctx->version.major ||
    server_version_major_minor__au8[1] != tls_ctx->version.minor)
  {
    // TODO: NEED TO SEND ALERT?
    FLEA_THROW("version mismatch", FLEA_ERR_TLS_GENERIC);
  }
  // TODO: in this part the client has to decide if he accepts the server's TLS version - implement negotiation
  // read random
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      tls_ctx->security_parameters.server_random.gmt_unix_time,
      4
    )
  );

  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
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
    FLEA_THROW("invalid session id length", FLEA_ERR_TLS_GENERIC);
  }

  FLEA_ALLOC_BUF(session_id__bu8, session_id_len__u8);

  FLEA_CCALL(THR_flea_rw_stream_t__force_read(hs_rd_stream__pt, session_id__bu8, session_id_len__u8));
  // TODO: STORE SESSION ID

  // read cipher suites
  FLEA_CCALL(THR_flea_rw_stream_t__force_read(hs_rd_stream__pt, ciphersuite__au8, sizeof(ciphersuite__au8)));

  // TODO: CHECK CIPHERSUITE
  // - must be among presented ones in client hello
  // read compression method
  // server_hello->compression_method = handshake_msg->data[length++];

  // server_compression_meth__u8 = handshake_msg->data[length++];

  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &server_compression_meth__u8));
  if(server_compression_meth__u8 != NO_COMPRESSION)
  {
    // TODO: NEED TO SEND ALERT?
    FLEA_THROW("unsupported compression method from server", FLEA_ERR_TLS_INV_ALGO_IN_SERVER_HELLO);
  }
  // TODO: parse extension
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
    FLEA_THROW("Header length field mismatch", FLEA_ERR_TLS_GENERIC);
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(session_id__bu8);
  );
} /* THR_flea_tls__read_server_hello */

static flea_err_t THR_flea_tls__send_client_hello(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
)
{
  FLEA_THR_BEG_FUNC();

  // calculate length for the header
  // TODO: include session id in the calculation (the 0 at 3rd place)
  // TODO: include cipher suites length instead of hard coded 2 (5+6th place)
  // TODO: include extensions length (last place)

  flea_u32_t len = 2 + 1 + 0 + 32 + 2 + 2 + 1 + 1 + 0;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      HANDSHAKE_TYPE_CLIENT_HELLO,
      len
    )
  );

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &tls_ctx->version.major, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &tls_ctx->version.minor, 1));

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters.client_random.gmt_unix_time,
      sizeof(tls_ctx->security_parameters.client_random.gmt_unix_time)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters.client_random.random_bytes,
      sizeof(tls_ctx->security_parameters.client_random.random_bytes)
    )
  );

  // session ID empty => no resumption (new handshake negotiation)
  // TODO: include possibility to resume a session
  flea_u8_t null_byte[] = {0};
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, null_byte, 1));

  // flea__encode_U32_BE(tls_ctx->allowed_cipher_suites_len, (flea_u8_t*)&buf);
  flea_u8_t cipher_suites_len[2];
  flea__encode_U16_BE(tls_ctx->allowed_cipher_suites_len, cipher_suites_len);

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, cipher_suites_len, 2));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->allowed_cipher_suites,
      tls_ctx->allowed_cipher_suites_len
    )
  );

  // compression methods: we don't support compression
  flea_u8_t one_byte[] = {1};
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, one_byte, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, null_byte, 1));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_client_hello */

static flea_err_t THR_flea_tls__send_client_key_exchange_rsa(
  flea_tls_ctx_t*    tls_ctx,
  flea_hash_ctx_t*   hash_ctx,
  flea_public_key_t* pubkey,
  flea_byte_vec_t*   premaster_secret__pt
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
  flea_al_u16_t result_len = (pubkey->key_bit_size__u16 + 7) / 8;
  flea_u8_t enc[256];
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
      hash_ctx,
      HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      encrypted__t.len__dtl + sizeof(len_enc)
    )
  );
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, len_enc, sizeof(len_enc)));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
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
  flea_tls_ctx_t*    tls_ctx,
  flea_hash_ctx_t*   hash_ctx,
  flea_public_key_t* pubkey,
  flea_byte_vec_t*   premaster_secret__pt
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls__send_client_key_exchange_rsa(tls_ctx, hash_ctx, pubkey, premaster_secret__pt));

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_handle_handsh_msg(
  flea_tls_ctx_t*              tls_ctx,
  flea_tls__handshake_state_t* handshake_state,
  flea_hash_ctx_t*             hash_ctx__pt
)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx->rec_prot__t));
  if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) != HANDSHAKE_TYPE_FINISHED)
  {
    FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, hash_ctx__pt));
  }
  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_HELLO)
    {
      FLEA_CCALL(THR_flea_tls__read_server_hello(tls_ctx, &handsh_rdr__t));
      printf("SM: read server hello\n");
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE
        | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
        | FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
        | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
    }
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE)
    {
      printf("SM: reading certificate\n");
      // Certificate certificate_message; // TODO: don't need this
      FLEA_CCALL(
        THR_flea_tls__read_certificate(
          tls_ctx,
          &handsh_rdr__t,
          &tls_ctx->server_pubkey
        )
      );

      // tls_ctx->server_pubkey = pubkey; // TODO: PUBKEY STILL NEEDED?
    }
    handshake_state->expected_messages ^= FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE;
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE)
  {
    // TODO: include here: FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE and FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_HELLO_DONE)
    {
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      if(flea_tls_handsh_reader_t__get_msg_rem_len(&handsh_rdr__t) != 0)
      {
        FLEA_THROW("invalid length of server hello done", FLEA_ERR_TLS_GENERIC);
      }
    }
    // TODO: NO ERROR WHEN MISSING?
  }
  else if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
    {
      FLEA_CCALL(THR_flea_tls__read_finished(tls_ctx, &handsh_rdr__t, hash_ctx__pt));

      printf("Handshake completed!\n");

      handshake_state->finished = FLEA_TRUE;
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
    }
  }
  FLEA_THR_FIN_SEC(
    flea_tls_handsh_reader_t__dtor(&handsh_rdr__t);
  );
} /* THR_flea_handle_handsh_msg */

flea_err_t THR_flea_tls__client_handshake(
  flea_tls_ctx_t*          tls_ctx,
  const flea_cert_store_t* trust_store__pt

  /*flea_u8_t*      trust_anchor__pu8,
   * flea_u16_t      trust_anchor_len__u16*/
  // flea_rw_stream_t* rw_stream__pt
)
{
  FLEA_THR_BEG_FUNC();

  /*
   * TODO: make this a real test case
   * flea_u8_t secret[] =   {0x9b, 0xbe, 0x43, 0x6b ,0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35} ;
   * flea_u8_t seed[] =     {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
   * flea_u8_t result[100];
   * //   flea_u8_t test_label[] =  {0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c};
   * PRF(secret, 16, PRF_LABEL_TEST, seed, 16, 100, result);
   *
   * printf("PRF TEST\n");
   * for (int i=0; i<100; i++)
   * {
   * printf("%02x ", result[i]);
   * }
   * printf("\n");
   */


  // define and init state
  flea_tls__handshake_state_t handshake_state; // TODO: INIT OBJECT
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_hash_ctx_t hash_ctx = flea_hash_ctx_t__INIT_VALUE;

  tls_ctx->trust_store__pt = trust_store__pt;
#ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE;
#else
  flea_u8_t premaster_secret__au8[256]; // TODO: SET CORRECT SIZE LIMIT
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_EMPTY_ALLOCATABLE(
    premaster_secret__au8,
    sizeof(premaster_secret__au8)
    );
#endif
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256)); // TODO: initialize properly
  while(1)
  {
    // initialize handshake by sending CLIENT_HELLO
    if(handshake_state.initialized == FLEA_FALSE)
    {
      // send client hello
      FLEA_CCALL(THR_flea_tls__send_client_hello(tls_ctx, &hash_ctx));
      printf("SM: sent client hello\n");
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
            &hash_ctx
          )
        );
        if(handshake_state.finished == FLEA_TRUE)
        {
          break;
        }
        continue;
        //    TODO: CALL CTORS FOR ALL OBJECTS

        // update hash for all incoming handshake messages
        // TODO: only include messages sent AFTER ClientHello. At the moment it could include HelloRequest received before sending HelloRequest

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
              &len_one__alu16
            )
          );
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
          printf("SM: switched on encryption on read\n");
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
      if(handshake_state.send_client_cert == FLEA_TRUE)
      {
        // TODO: send certificate message
      }

      printf("SM sending client key_ex\n");
      // TODO: INIT PUBKEY IN CTOR!
      FLEA_CCALL(
        THR_flea_tls__send_client_key_exchange(
          tls_ctx,
          &hash_ctx,
          &tls_ctx->server_pubkey,
          &premaster_secret__t
        )
      );
      printf("SM sending change cipherspec\n");
      FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx, &hash_ctx));

      /*
       * Enable encryption for outgoing messages
       */

      FLEA_CCALL(
        THR_flea_tls__create_master_secret(
          tls_ctx->security_parameters.client_random,
          tls_ctx->security_parameters.server_random,
          // tls_ctx->premaster_secret,
          &premaster_secret__t,
          tls_ctx->security_parameters.master_secret
        )
      );
      FLEA_CCALL(THR_flea_tls__generate_key_block(tls_ctx, tls_ctx->key_block));

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

      printf("SM: ...switched on encryption on write\n");
      FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &hash_ctx));
      printf("SM: sent finished\n");

      handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
      continue;
    }
  }
  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&premaster_secret__t);
  );
} /* THR_flea_tls__client_handshake */
