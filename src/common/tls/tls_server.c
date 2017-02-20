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
#include "flea/pk_api.h"

flea_err_t THR_flea_tls__read_client_hello(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u8_t client_version_major_minor__au8[2];
  flea_u8_t session_id_len__u8;

  // TODO: free buf fehlt:
  FLEA_DECL_BUF(session_id__bu8, flea_u8_t, 32);
  const flea_al_u8_t max_session_id_len__alu8 = 32;
  flea_u8_t client_compression_methods_len__u8;
  flea_u16_t cipher_suites_len__u16;
  flea_bool_t found_compression_method;
  const flea_u16_t max_extension_len__u16 = 100; // max size for one extension
  FLEA_DECL_BUF(extension__bu8, flea_u8_t, 100); // TODO: think about the max buffer size !
  flea_u16_t all_extensions_len__u16;
  flea_u16_t extension_len__u16;
  flea_u8_t extension_type__au8[2]; // TODO: meaningful representation of extension type
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
      tls_ctx->security_parameters.client_random.gmt_unix_time,
      4
    )
  );
  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      hs_rd_stream__pt,
      tls_ctx->security_parameters.client_random.random_bytes,
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
  if(cipher_suites_len__u16 % 2 != 0)
  {
    FLEA_THROW("incorrect cipher suites length", FLEA_ERR_TLS_GENERIC);
  }

  // TODO: need to choose the "best" cipher suite
  // TODO: everything declared and defined locally because there is no
  // consistent implementation for the cipher suites yet
  flea_bool_t found = FLEA_FALSE;
  flea_u8_t curr_cs__au8[2];
  flea_u8_t supported_cs__au8[2]   = {0x00, 0x3d}; // RSA AES256 CBC SHA256
  flea_u16_t supported_cs_len__u16 = 2;
  flea_u16_t supported_cs_index__u16;
  flea_u8_t chosen_cs__au8[2];
  // TODO: mit u16 arbeiten für die Ciphersuites statt mit 2-byte Arrays
  flea_u16_t chosen_cs_index__u16 = supported_cs_len__u16; // TODO: Falko: Off by one  ?
  while(cipher_suites_len__u16)
  {
    FLEA_CCALL(THR_flea_rw_stream_t__force_read(hs_rd_stream__pt, curr_cs__au8, 2));

    // iterate over all supported cipher suites
    supported_cs_index__u16 = 0;
    while(supported_cs_index__u16 < supported_cs_len__u16)
    {
      // TODO: endianess!!
      if(curr_cs__au8[0] == supported_cs__au8[supported_cs_index__u16] &&
        curr_cs__au8[1] == supported_cs__au8[supported_cs_index__u16 + 1])
      {
        if(supported_cs_index__u16 < chosen_cs_index__u16)
        {
          chosen_cs_index__u16 = supported_cs_index__u16;
          chosen_cs__au8[0]    = supported_cs__au8[chosen_cs_index__u16];
          chosen_cs__au8[1]    = supported_cs__au8[chosen_cs_index__u16];
          found = FLEA_TRUE;
        }
      }
      supported_cs_index__u16 += 2;
    }
    cipher_suites_len__u16 -= 2;
  }
  if(found == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on cipher", FLEA_ERR_TLS_GENERIC);
  }


  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &client_compression_methods_len__u8));

  flea_u8_t curr_cm;
  while(client_compression_methods_len__u8)
  {
    FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, &curr_cm));
    if(curr_cm == NO_COMPRESSION)
    {
      found_compression_method = FLEA_TRUE;
      break;
    }
    client_compression_methods_len__u8--;
  }
  if(found_compression_method == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on compression method", FLEA_ERR_TLS_GENERIC);
  }

  // if there are still bytes left to read, they must be from extensions
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    // read extension length
    // TODO: stream function to read in the length
    // TODO: Falko: Die wird kommen, aber bis dahin bitte Endianess-unabhängig
    // dekodieren
    FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, ((flea_u8_t*) &all_extensions_len__u16) + 1));
    FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, (flea_u8_t*) &all_extensions_len__u16));

    // read extensions
    FLEA_ALLOC_BUF(extension__bu8, max_extension_len__u16); // TODO/QUESTION: Alloc anew for every extension or simply use the max extension length?
    // ANSWER(Falko): Im es müssen die Extensions, die wir unterstützen,
    // verarbeitet werden können. Das sollte dann in Unterfunktionen erfolgen.
    // Somit brauchen wir hier keinen Buffer.
    // Da wir noch keine Extensions unterstützen, sollten die Daten im Moment
    // nur weggelesen werden. Dafür wird es auch noch unterstützung im Stream
    // geben ('skip').
    while(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) > 0)
    {
      // read type
      FLEA_CCALL(
        THR_flea_rw_stream_t__force_read(
          hs_rd_stream__pt,
          extension_type__au8,
          2
        )
      );

      // read length
      // TODO: use stream function for decoding
      // TODO: Falko: Die wird kommen, aber bis dahin bitte Endianess-unabhängig
      // dekodieren
      FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, ((flea_u8_t*) &extension_len__u16) + 1));
      FLEA_CCALL(THR_flea_rw_stream_t__read_byte(hs_rd_stream__pt, (flea_u8_t*) &extension_len__u16));

      if(extension_len__u16 > max_extension_len__u16)
      {
        FLEA_THROW("extension too long to be processed", FLEA_ERR_TLS_GENERIC);
      }
      FLEA_CCALL(
        THR_flea_rw_stream_t__force_read(
          hs_rd_stream__pt,
          extension__bu8,
          extension_len__u16
        )
      );

      // TODO: implement handle_extension function that processes the extensions
    }
  }
  // check length in the header field for integrity
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("Header length field mismatch", FLEA_ERR_TLS_GENERIC);
  }


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(session_id__bu8);
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
      tls_ctx->security_parameters.server_random.gmt_unix_time,
      sizeof(tls_ctx->security_parameters.server_random.gmt_unix_time)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters.server_random.random_bytes,
      sizeof(tls_ctx->security_parameters.server_random.random_bytes)
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

/*
 * Note: The version number in the PreMasterSecret is the version
 * offered by the client in the ClientHello.client_version, not the
 * version negotiated for the connection.
 *
 */
static flea_err_t THR_flea_tls__read_client_key_exchange_rsa(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_ref_cu8_t*           server_key__pt,
  flea_byte_vec_t*          premaster_secret__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u16_t enc_premaster_secret_len__u16;
  flea_private_key_t key__t;
  const flea_u16_t max_enc_premaster_secret_len__u16 = 256;

  // flea_al_u16_t premaster_secret__len_u16 = 256;

  FLEA_DECL_BUF(enc_premaster_secret__bu8, flea_u8_t, 256); // TODO: need more ?
  // FLEA_DECL_BUF(premaster_secret__bu8, flea_u8_t, 256); // always 48 byte but could be more if it is manipulated
  FLEA_THR_BEG_FUNC();


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

  // read server key
  // TODO: do one time when initializing TLS?
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&key__t, server_key__pt->data__pcu8, server_key__pt->len__dtl));

  FLEA_CCALL(
    THR_flea_pk_api__decrypt_message(
      flea_rsa_pkcs1_v1_5_encr,
      flea_sha256,
      enc_premaster_secret__bu8,
      enc_premaster_secret_len__u16,
      premaster_secret__pt,

      /*tls_ctx->premaster_secret,
       * &premaster_secret__len_u16,*/
      &key__t,
      48
    )
  );


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(enc_premaster_secret__bu8);
  );
} /* THR_flea_tls__read_client_key_exchange_rsa */

static flea_err_t THR_flea_tls__read_client_key_exchange(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_ref_cu8_t*           server_key__pt,
  flea_byte_vec_t*          premaster_secret__pt
)
{
  FLEA_THR_BEG_FUNC();

  // TODO: choose appropriate function
  FLEA_CCALL(THR_flea_tls__read_client_key_exchange_rsa(tls_ctx, hs_rdr__pt, server_key__pt, premaster_secret__pt));

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_handle_handsh_msg(
  flea_tls_ctx_t*              tls_ctx,
  flea_tls__handshake_state_t* handshake_state,
  flea_hash_ctx_t*             hash_ctx__pt,
  flea_ref_cu8_t*              server_key__pt,
  flea_byte_vec_t*             premaster_secret__pt
)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  FLEA_DECL_OBJ(hash_ctx_copy_read_finished__t, flea_hash_ctx_t);

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx->rec_prot__t));
  if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
  {
    /*
     * for read_finished use a copy of hash_ctx where the finished message is not included yet
     */
    FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_copy_read_finished__t, hash_ctx__pt));
  }
  FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, hash_ctx__pt));


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
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY
      | FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE)
    {
      FLEA_CCALL(THR_flea_tls__read_client_key_exchange(tls_ctx, &handsh_rdr__t, server_key__pt, premaster_secret__pt));
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
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
    {
      FLEA_CCALL(THR_flea_tls__read_finished(tls_ctx, &handsh_rdr__t, &hash_ctx_copy_read_finished__t));
      // FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, hash_ctx__pt));

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

#ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE;
#else
  flea_u8_t premaster_secret__au8[256]; // TODO: SET CORRECT SIZE LIMIT
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_EMPTY_ALLOCATABLE(
    premaster_secret__au8,
    sizeof(premaster_secret__au8)
    );
#endif
  // TODO: propably better to do it somewhere else
  tls_ctx->security_parameters.connection_end = FLEA_TLS_SERVER;

  // define and init state
  flea_tls__handshake_state_t handshake_state;
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_hash_ctx_t hash_ctx;
  THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256); // TODO: initialize properly

  // flea_public_key_t pubkey; // TODO: -> tls_ctx


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
        FLEA_CCALL(
          THR_flea_handle_handsh_msg(
            tls_ctx,
            &handshake_state,
            &hash_ctx,
            server_key__pt,
            &premaster_secret__t
          )
        );
        // FLEA_CCALL(THR_flea_tls__read_handshake_message(tls_ctx, &recv_handshake, &hash_ctx));
      }
      else if(cont_type__e == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(!(handshake_state.expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC))
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
        }
        else
        {
          printf("SM: Processing ChangeCipherSpec\n");

          flea_u8_t dummy_byte;
          flea_al_u16_t len_one__alu16 = 1;

          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__read_data(
              &tls_ctx->rec_prot__t,
              CONTENT_TYPE_CHANGE_CIPHER_SPEC,
              &dummy_byte,
              &len_one__alu16
            )
          );

          /*
           * Enable encryption for incoming messages
           */
          // setup key material
          FLEA_CCALL(
            THR_flea_tls__create_master_secret(
              tls_ctx->security_parameters.client_random,
              tls_ctx->security_parameters.server_random,
              &premaster_secret__t,
              // tls_ctx->premaster_secret,
              tls_ctx->security_parameters.master_secret
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
              tls_ctx->key_block + 2 * 32,
              32,
              tls_ctx->key_block,
              32,
              32
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
        printf("SM: sending change cipherspec\n");
        FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx, &hash_ctx));

        printf("SM: switching on encryption on write...\n");
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
            &tls_ctx->rec_prot__t,
            flea_tls_write,
            flea_aes256,
            flea_sha256,
            flea_hmac_sha256,
            tls_ctx->key_block + 2 * 32 + 32,
            32,
            tls_ctx->key_block + 32,
            32,
            32
          )
        );


        FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &hash_ctx));
        printf("SM: sent finished\n");

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
