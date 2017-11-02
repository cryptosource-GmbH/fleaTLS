/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "internal/common/tls/tls_session_mngr_int.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "flea/tls_server.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"
#include "flea/rng.h"
#include "flea/pkcs8.h"
#include "flea/rsa.h"
#include "flea/pk_api.h"
#include "internal/common/tls/parallel_hash.h"
#include "flea/hash.h"
#include "flea/ec_key_gen.h"
#include "flea/byte_vec.h"
#include "flea/ecka.h"
#include "internal/pltf_if/time.h"

#ifdef FLEA_HAVE_TLS

static flea_err_t THR_flea_tls__read_client_hello(
  flea_tls_server_ctx_t*    server_ctx__pt,
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt
)
{
  flea_tls_ctx_t* tls_ctx = &server_ctx__pt->tls_ctx__t;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u8_t client_version_major_minor__au8[2];
  flea_u8_t session_id_len__u8;
  flea_bool_t found_sec_reneg__b = FLEA_FALSE;
  flea_bool_t found = FLEA_FALSE;
  flea_u16_t supported_cs_len__u16 = tls_ctx->allowed_cipher_suites__prcu16->len__dtl;
  flea_u16_t supported_cs_index__u16;
  flea_u16_t chosen_cs_index__u16 = supported_cs_len__u16;

  // TODO: NEED ONLY THE DEFINED SERVER SESSION ID LEN:
  // UPDATE(JR): so buffer size is FLEA_TLS_SESSION_ID_LEN ? And we need to
  // check for length == 0 or length == FLEA_TLS_SESSION_ID_LEN and discard any
  // other possible length?
  FLEA_DECL_BUF(session_id__bu8, flea_u8_t, 32);
  const flea_al_u8_t max_session_id_len__alu8 = 32;
  flea_u8_t client_compression_methods_len__u8;
  flea_u16_t cipher_suites_len_from_peer__u16;
  flea_bool_t found_compression_method;
  flea_bool_t client_presented_sec_reneg_fallback_ciph_suite__b = FLEA_FALSE;

# ifdef FLEA_HAVE_ECC
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    peer_cipher_suites_u16_be__t,
    FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE
  );
# endif
  FLEA_THR_BEG_FUNC();


  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) < 34)
  {
    FLEA_THROW("message too short", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  // read version
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      client_version_major_minor__au8,
      sizeof(client_version_major_minor__au8)
    )
  );

  if(client_version_major_minor__au8[0] != tls_ctx->version.major ||
    client_version_major_minor__au8[1] != tls_ctx->version.minor)
  {
    FLEA_THROW("Version mismatch!", FLEA_ERR_TLS_UNSUPP_PROT_VERSION);
  }

  // read random
  // TODO: CHECK HOW TIME IS TO BE USED AND THEN ENCODE IT CORRECTLY

  /*  FLEA_CCALL(
   *  THR_flea_rw_stream_t__read_full(
   *    hs_rd_stream__pt,
   *    tls_ctx->client_random.gmt_unix_time,
   *    4
   *  )
   * );*/
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      // tls_ctx->client_and_server_random__bu8,
      hs_ctx__pt->client_and_server_random__pt->data__pu8,
      FLEA_TLS_HELLO_RANDOM_SIZE
    )
  );


  // read session id length
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      hs_rd_stream__pt,
      &session_id_len__u8
    )
  );
  if(session_id_len__u8 > max_session_id_len__alu8)
  {
    FLEA_THROW("invalid session id length", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  // read session id
  FLEA_ALLOC_BUF(session_id__bu8, session_id_len__u8);
  // TODO: SKIP DATA IF LONGER THAN DEFINED SERVER SESSION ID LEN
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      session_id__bu8,
      session_id_len__u8
    )
  );
  server_ctx__pt->server_resume_session__u8      = 0;
  server_ctx__pt->server_session_id_assigned__u8 = (session_id_len__u8 != 0);
  if(session_id_len__u8 && server_ctx__pt->session_mngr_mbn__pt)
  {
    flea_bool_t resume__b;
    FLEA_CCALL(
      THR_flea_tls_session_mngr_t__load_session(
        server_ctx__pt->session_mngr_mbn__pt,
        session_id__bu8,
        session_id_len__u8,
        &server_ctx__pt->active_session__t,
        &resume__b
      )
    );

    server_ctx__pt->server_resume_session__u8 = resume__b;
  }

  FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(hs_rd_stream__pt, (flea_u32_t*) &cipher_suites_len_from_peer__u16, 2));

  if(cipher_suites_len_from_peer__u16 % 2 != 0)
  {
    FLEA_THROW("incorrect cipher suites length", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

# ifdef FLEA_USE_HEAP_BUF
  if(cipher_suites_len_from_peer__u16 > FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE_HEAP)
  {
    FLEA_THROW("cipher suites length too large", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
# endif
# ifndef FLEA_USE_HEAP_BUF
  if(cipher_suites_len_from_peer__u16 > FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE)
  {
    FLEA_THROW("buffer not large enough to store cipher suites", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
# endif

  while(cipher_suites_len_from_peer__u16)
  {
    flea_u8_t curr_cs__au8[2];
    flea_al_u16_t curr_cs_from_peer__alu16;
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        curr_cs__au8,
        2
      )
    );
    curr_cs_from_peer__alu16 = curr_cs__au8[0] << 8 | curr_cs__au8[1];
    if(curr_cs_from_peer__alu16 == FLEA_TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    {
      client_presented_sec_reneg_fallback_ciph_suite__b = FLEA_TRUE;
    }

    // check that key type of cert matches cs kex
    if(tls_ctx->private_key__pt->key_type__t == flea_tls__get_key_type_by_cipher_suite_id(curr_cs_from_peer__alu16))
    {
# ifndef FLEA_HAVE_ECC
      // iterate over all supported cipher suites
      supported_cs_index__u16 = 0;
      while(supported_cs_index__u16 < supported_cs_len__u16)
      {
        if(curr_cs_from_peer__alu16 == tls_ctx->allowed_cipher_suites__prcu16->data__pcu16[ supported_cs_index__u16 ])
        {
          if(supported_cs_index__u16 < chosen_cs_index__u16)
          {
            chosen_cs_index__u16 = supported_cs_index__u16;
            tls_ctx->selected_cipher_suite__u16 = curr_cs_from_peer__alu16;
            found = FLEA_TRUE;
            break;
          }
        }
        supported_cs_index__u16 += 1;
      }
# else /* ifndef FLEA_HAVE_ECC */
      FLEA_CCALL(THR_flea_byte_vec_t__append(&peer_cipher_suites_u16_be__t, curr_cs__au8, sizeof(curr_cs__au8)));
# endif /* ifndef FLEA_HAVE_ECC */
    }
    cipher_suites_len_from_peer__u16 -= 2;
  }

# ifndef FLEA_HAVE_ECC
  if(found == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on cipher", FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CIPHERSUITE);
  }
# endif

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      hs_rd_stream__pt,
      &client_compression_methods_len__u8
    )
  );

  flea_u8_t curr_cm;
  while(client_compression_methods_len__u8)
  {
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_byte(
        hs_rd_stream__pt,
        &curr_cm
      )
    );
    if(curr_cm == NO_COMPRESSION)
    {
      found_compression_method = FLEA_TRUE;
      break;
    }
    client_compression_methods_len__u8--;
  }
  if(found_compression_method == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on compression method", FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CMPR_METH);
  }

  // if there are still bytes left to read, they must be from extensions
  // if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  // {
  FLEA_CCALL(
    THR_flea_tls_ctx_t__parse_hello_extensions(
      tls_ctx,
      hs_rdr__pt,
      &found_sec_reneg__b,
      tls_ctx->private_key__pt
    )
  );
  // }
  if(tls_ctx->sec_reneg_flag__u8 && !found_sec_reneg__b)
  {
    FLEA_THROW("missing renegotiation info in peer's extensions", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

# ifdef FLEA_HAVE_ECC
  {
    flea_al_u16_t curr_cs_from_peer__alu16;
    flea_al_u16_t i;
    for(i = 0; i < peer_cipher_suites_u16_be__t.len__dtl; i += 2)
    {
      curr_cs_from_peer__alu16 = flea__decode_U16_BE(&peer_cipher_suites_u16_be__t.data__pu8[i]);

      supported_cs_index__u16 = 0;
      while(supported_cs_index__u16 < supported_cs_len__u16)
      {
        if(curr_cs_from_peer__alu16 == tls_ctx->allowed_cipher_suites__prcu16->data__pcu16[ supported_cs_index__u16 ])
        {
          if(flea_tls__is_cipher_suite_ecc_suite(curr_cs_from_peer__alu16))
          {
            // TODO: if multiple certs are supported, then the choice of the
            // suite is more complicated:
            // - server must check that for the candidate cipher suite and the
            // client-supplied curves a fitting certificate is available
            // - for this purpose extension_ctrl__u8's UNMATCHING bit must
            // rather somehow represent a list of ciphersuites resulting from
            // the available certificates
            if(tls_ctx->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__UNMATCHING)
            {
              supported_cs_index__u16 += 1;
              break;
            }
          }


          // we can only use ECDHE if the certificate type matches the kex
          // type of the cipher suite and if the signature algorithms extension
          // offers an appropriate signature algorithm
          if(flea_tls__is_cipher_suite_ecdhe_suite(curr_cs_from_peer__alu16))
          {
            // check if we can use ECDHE according to the signature algorithms
            // extension
            if(tls_ctx->can_use_ecdhe == FLEA_TRUE)
            { }
            else
            {
              // supported_cs_index__u16 += 1;
              // continue;
              break;
            }
          }

          if(supported_cs_index__u16 < chosen_cs_index__u16)
          {
            chosen_cs_index__u16 = supported_cs_index__u16;
            tls_ctx->selected_cipher_suite__u16 = curr_cs_from_peer__alu16;
            found = FLEA_TRUE;
            break;
          }
        }
        supported_cs_index__u16 += 1;
      }
    }
    if(found == FLEA_FALSE)
    {
      FLEA_THROW("Could not agree on cipher", FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CIPHERSUITE);
    }
  }
# endif /* ifdef FLEA_HAVE_ECC */

  // check length in the header field for integrity
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("Header length field mismatch", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  if(found_sec_reneg__b || client_presented_sec_reneg_fallback_ciph_suite__b)
  {
    tls_ctx->sec_reneg_flag__u8    = FLEA_TRUE;
    tls_ctx->allow_insec_reneg__u8 = FLEA_FALSE;
  }
  else if(tls_ctx->allow_insec_reneg__u8 == FLEA_FALSE)
  {
    tls_ctx->allow_reneg__u8 = FLEA_FALSE;
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(session_id__bu8);
    flea_byte_vec_t__dtor(&peer_cipher_suites_u16_be__t);
  );
} /* THR_flea_tls__read_client_hello */

static flea_err_t THR_flea_tls__send_server_hello(
  flea_tls_server_ctx_t*        server_ctx__pt,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx
)
{
  flea_u8_t suite__au8[2];
  flea_u8_t session_id_len__u8 = 0;
  flea_al_u16_t ext_len__alu16;
  flea_u32_t len;
  const flea_u8_t null_byte = 0;
  flea_u8_t version__au8[2];

  flea_tls_ctx_t* tls_ctx = &server_ctx__pt->tls_ctx__t;

  FLEA_THR_BEG_FUNC();
  ext_len__alu16 = flea_tls_ctx_t__compute_extensions_length(tls_ctx);
  len  = 2 + 32 + 1 + /*32 +*/ 2 + 1;
  len += ext_len__alu16;
  if(ext_len__alu16)
  {
    /* for encoding of extensions length */
    len += 2;
  }
  if(server_ctx__pt->session_mngr_mbn__pt)
  {
    session_id_len__u8 = FLEA_TLS_SESSION_ID_LEN;
    len += FLEA_TLS_SESSION_ID_LEN;
  }

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_SERVER_HELLO,
      len
    )
  );

  version__au8[0] = tls_ctx->version.major;
  version__au8[1] = tls_ctx->version.minor;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      version__au8,
      sizeof(version__au8)
    )
  );


  /*FLEA_CCALL(
   * THR_flea_tls__send_handshake_message_content(
   *  &tls_ctx->rec_prot__t,
   *  hash_ctx,
   *  tls_ctx->server_random.gmt_unix_time,
   *  sizeof(tls_ctx->server_random.gmt_unix_time)
   * )
   * );*/
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      // tls_ctx->client_and_server_random__bu8 + FLEA_TLS_HELLO_RANDOM_SIZE,
      hs_ctx__pt->client_and_server_random__pt->data__pu8 + FLEA_TLS_HELLO_RANDOM_SIZE,
      FLEA_TLS_HELLO_RANDOM_SIZE
    )
  );

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, &session_id_len__u8, 1));
  // if(tls_ctx->server_active_sess_mbn__pt)
  // {
  if(!server_ctx__pt->server_resume_session__u8 && server_ctx__pt->session_mngr_mbn__pt)
  {
    FLEA_CCALL(THR_flea_rng__randomize(server_ctx__pt->active_session__t.session_id__au8, FLEA_TLS_SESSION_ID_LEN));

    FLEA_CCALL(THR_flea_pltfif_time__get_current_time(&server_ctx__pt->active_session__t.valid_until__t));
    flea_gmt_time_t__add_seconds_to_date(
      &server_ctx__pt->active_session__t.valid_until__t,
      server_ctx__pt->session_mngr_mbn__pt->session_validity_period_seconds__u32
    );
  }

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      server_ctx__pt->active_session__t.session_id__au8,
      session_id_len__u8
    )
  );
  // }
  suite__au8[0] = tls_ctx->selected_cipher_suite__u16 >> 8;
  suite__au8[1] = tls_ctx->selected_cipher_suite__u16;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      suite__au8,
      sizeof(suite__au8)
    )
  );

  // We don't support compression
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, &null_byte, 1));

  FLEA_CCALL(THR_flea_tls_ctx_t__send_extensions_length(tls_ctx, p_hash_ctx));
  if(flea_tls_ctx_t__do_send_sec_reneg_ext(tls_ctx))
  {
    FLEA_CCALL(THR_flea_tls_ctx_t__send_reneg_ext(tls_ctx, p_hash_ctx));
  }
  if(flea_tls__is_cipher_suite_ecc_suite(tls_ctx->selected_cipher_suite__u16))
  {
    /*if(tls_ctx->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES)
     * {
     * FLEA_CCALL(THR_flea_tls_ctx_t__send_ecc_supported_curves_ext(tls_ctx, p_hash_ctx));
     * }*/
    if(tls_ctx->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__send_ecc_point_format_ext(tls_ctx, p_hash_ctx));
    }
  }
  // if(flea_tls_ctx_t__is_ecc_suite(tls_ctx__pt) &&

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_server_hello */

static flea_err_t THR_flea_tls_get_sig_length_of_priv_key(
  flea_private_key_t* priv_key__pt,
  flea_u16_t*         len__u16
)
{
  FLEA_THR_BEG_FUNC();
  if(priv_key__pt->key_type__t == flea_rsa_key)
  {
    *len__u16 = (priv_key__pt->key_bit_size__u16 + 7) / 8;
  }
  else
  {
    FLEA_THROW("not yet implemented", FLEA_ERR_INV_ARG);
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls__send_server_kex(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_private_key_t*           ecdhe_priv_key__pt
)
{
  flea_tls__kex_method_t kex_method__t;

  FLEA_DECL_OBJ(params_hash_ctx__t, flea_hash_ctx_t);
  FLEA_DECL_BUF(hash__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(sig_vec__t, FLEA_MAX_SIG_SIZE);
  flea_u8_t hash_out_len__u8;
  flea_u32_t hdr_len__u32;
  flea_ref_cu8_t pub_point__rcu8;
  flea_u8_t ec_curve_type__au8[] = {3}; // named_curve has value 3
  flea_hash_id_t hash_id__t;
  flea_pk_scheme_id_t pk_scheme_id__t;
  flea_u8_t sig_and_hash_alg[2];
  flea_u16_t sig_len__u16;
  flea_u8_t ec_curve__au8[2];
  flea_u8_t sig_len_enc__au8[2];
  flea_public_key_t ecdhe_pub_key__t = flea_public_key_t__INIT_VALUE;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls__map_flea_curve_to_curve_bytes(tls_ctx__pt->chosen_ecc_dp_internal_id__u8, ec_curve__au8));

  hash_id__t      = tls_ctx__pt->chosen_hash_algorithm__t;
  pk_scheme_id__t = flea_tls__get_sig_alg_from_key_type(tls_ctx__pt->private_key__pt->key_type__t);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&params_hash_ctx__t, hash_id__t));
  hash_out_len__u8 = flea_hash_ctx_t__get_output_length(&params_hash_ctx__t);
  FLEA_CCALL(THR_flea_tls__map_flea_hash_to_tls_hash(hash_id__t, &sig_and_hash_alg[0]));
  FLEA_CCALL(THR_flea_tls__map_flea_sig_to_tls_sig(pk_scheme_id__t, &sig_and_hash_alg[1]));

  FLEA_CCALL(THR_flea_tls_get_sig_length_of_priv_key(tls_ctx__pt->private_key__pt, &sig_len__u16));

  kex_method__t = flea_tls_get_kex_method_by_cipher_suite_id(
    (flea_tls__cipher_suite_id_t) tls_ctx__pt->selected_cipher_suite__u16
    );

  if(kex_method__t == FLEA_TLS_KEX_ECDHE)
  {
    // create ECDHE key pair
    FLEA_CCALL(
      THR_flea_tls__create_ecdhe_key(
        // &tls_ctx__pt->ecdhe_priv_key__t,
        ecdhe_priv_key__pt,
        &ecdhe_pub_key__t,
        (flea_ec_dom_par_id_t) tls_ctx__pt->chosen_ecc_dp_internal_id__u8
      )
    );

    pub_point__rcu8 = flea_public_key__get_encoded_public_component(&ecdhe_pub_key__t);

    // TODO: for ECDSA send header after calculating sig, because size is
    // unknown beforehand
    hdr_len__u32 = 3 + 1 + pub_point__rcu8.len__dtl + 2 + 2 + sig_len__u16; // 3 for named curve + 1 for pub point length + 2 for sig/hash alg + 2 sig length + 256 for sha256 sig

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_hdr(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
        hdr_len__u32
      )
    );

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        ec_curve_type__au8,
        1
      )
    );

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        ec_curve__au8,
        2
      )
    );


    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        (flea_u8_t*) &pub_point__rcu8.len__dtl,
        1
      )
    );

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        pub_point__rcu8.data__pcu8,
        pub_point__rcu8.len__dtl
      )
    );


    flea__encode_U16_BE(sig_len__u16, sig_len_enc__au8);

    // calculate hash of ec params
    FLEA_CCALL(
      THR_flea_hash_ctx_t__update(
        &params_hash_ctx__t,
        // tls_ctx__pt->client_and_server_random__bu8,
        hs_ctx__pt->client_and_server_random__pt->data__pu8,
        2 * FLEA_TLS_HELLO_RANDOM_SIZE
      )
    );
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, ec_curve_type__au8, sizeof(ec_curve_type__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, ec_curve__au8, sizeof(ec_curve__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, (flea_u8_t*) &pub_point__rcu8.len__dtl, 1));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, pub_point__rcu8.data__pcu8, pub_point__rcu8.len__dtl));

    FLEA_ALLOC_BUF(hash__bu8, hash_out_len__u8);
    FLEA_CCALL(THR_flea_hash_ctx_t__final(&params_hash_ctx__t, hash__bu8));


    // create signature
    FLEA_CCALL(
      THR_flea_private_key_t__sign_digest_plain_format(
        tls_ctx__pt->private_key__pt,
        pk_scheme_id__t,
        hash_id__t,
        hash__bu8,
        hash_out_len__u8,
        &sig_vec__t
      )
    );

    // send sig_hash alg + sig
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        sig_and_hash_alg,
        2
      )
    );


    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        sig_len_enc__au8,
        sizeof(sig_len_enc__au8)
      )
    );


    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        sig_vec__t.data__pu8,
        sig_vec__t.len__dtl
      )
    );
  }
  else
  {
    // should never come this far if we don't support the cipher suite / kex
    FLEA_THROW("Invalid state", FLEA_ERR_TLS_INVALID_STATE);
  }

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&params_hash_ctx__t);
    FLEA_FREE_BUF_FINAL(hash__bu8);
    flea_byte_vec_t__dtor(&sig_vec__t);
    flea_public_key_t__dtor(&ecdhe_pub_key__t);
  );
} /* THR_flea_tls__send_server_kex */

/*
 *  if 'allowed_sig_algs__u8' is not already accounted for, adjust cert_types_mask__u8 and return true
 */
static flea_bool_t flea_tls__is_allowed_cert_type_hlp_fct(
  flea_pk_scheme_id_t pk_scheme_id__t,
  flea_u8_t*          cert_types_mask__u8,
  flea_u8_t           allowed_sig_algs__u8
)
{
  flea_tls_client_cert_type_e cl_cert_type__e;

  if(pk_scheme_id__t == flea_rsa_pkcs1_v1_5_sign)
  {
    cl_cert_type__e = flea_tls_cl_cert__rsa_sign;
  }

  /*
   * add more options when they are supported
   */
  else
  {
    cl_cert_type__e = flea_tls_cl_cert__ecdsa_sign;
  }

  if(allowed_sig_algs__u8 == pk_scheme_id__t)
  {
    if((*cert_types_mask__u8 | cl_cert_type__e) != *cert_types_mask__u8)
    {
      *cert_types_mask__u8 |= flea_tls_cl_cert__rsa_sign;
      return FLEA_TRUE;
    }
  }

  return FLEA_FALSE;
}

static flea_err_t THR_flea_tls__send_cert_request(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx
)
{
  const flea_pk_scheme_id_t supported_pk_schemes__at[] = {
# ifdef FLEA_HAVE_RSA
    flea_rsa_pkcs1_v1_5_sign,
# endif
# ifdef FLEA_HAVE_ECDSA
    flea_ecdsa_emsa1,
# endif
  };
  flea_u8_t cert_types__au8[FLEA_NB_ARRAY_ENTRIES(supported_pk_schemes__at)];
  flea_u8_t cert_types_len__u8  = 0;
  flea_u8_t cert_types_mask__u8 = 0;

  flea_u8_t cert_authorities_len_enc__au8[2];
  flea_u16_t cert_authorities_len__u16 = 0;

  flea_u32_t hdr_len__u32;

  FLEA_THR_BEG_FUNC();

  // determine what certificate types we allow based on the allowed signature
  // algorithms
  for(flea_u8_t i = 1; i < tls_ctx->allowed_sig_algs__rcu8.len__dtl; i += 2)
  {
    for(flea_u8_t j = 0; j < sizeof(supported_pk_schemes__at) / sizeof(flea_pk_scheme_id_t); j++)
    {
      if(flea_tls__is_allowed_cert_type_hlp_fct(
          supported_pk_schemes__at[j],
          &cert_types_mask__u8,
          tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i]
        ) == FLEA_TRUE)
      {
        if(cert_types_len__u8 >= sizeof(cert_types__au8))
        {
          FLEA_THROW("cert types buffer too small", FLEA_ERR_INT_ERR);
        }
        cert_types__au8[cert_types_len__u8++] = flea_tls__get_tls_cert_type_from_flea_pk_scheme(
          supported_pk_schemes__at[j]
          );
      }
    }
  }

  hdr_len__u32 = 1 + cert_types_len__u8 + 2 + tls_ctx->allowed_sig_algs__rcu8.len__dtl + 2 + cert_authorities_len__u16;

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
      hdr_len__u32
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      &cert_types_len__u8,
      1
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      cert_types__au8,
      cert_types_len__u8
    )
  );

  // send sig algs length
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_int_be(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      tls_ctx->allowed_sig_algs__rcu8.len__dtl,
      2
    )
  );

  // send sig algs
  for(int i = 0; i < tls_ctx->allowed_sig_algs__rcu8.len__dtl; i += 2)
  {
    flea_u8_t tmp_buf__au8[2];
    FLEA_CCALL(
      THR_flea_tls__map_flea_hash_to_tls_hash(
        (flea_hash_id_t) tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i],
        &tmp_buf__au8[0]
      )
    );

    FLEA_CCALL(
      THR_flea_tls__map_flea_sig_to_tls_sig(
        (flea_pk_scheme_id_t) tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i + 1],
        &tmp_buf__au8[1]
      )
    );

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        tmp_buf__au8,
        sizeof(tmp_buf__au8)
      )
    );
  }

  flea__encode_U16_BE(cert_authorities_len__u16, cert_authorities_len_enc__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      cert_authorities_len_enc__au8,
      2
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_cert_request */

/*
 * Note: The version number in the PreMasterSecret is the version
 * offered by the client in the ClientHello.client_version, not the
 * version negotiated for the connection.
 *
 */
# ifdef FLEA_HAVE_RSA
static flea_err_t THR_flea_tls__read_client_key_exchange_rsa(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_byte_vec_t*          premaster_secret__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u32_t enc_premaster_secret_len__u32;

  FLEA_DECL_BUF(enc_premaster_secret__bu8, flea_u8_t, FLEA_RSA_MAX_MOD_BYTE_LEN);
  FLEA_THR_BEG_FUNC();

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(hs_rd_stream__pt, &enc_premaster_secret_len__u32, 2));
  if(enc_premaster_secret_len__u32 > tls_ctx->private_key__pt->max_primitive_input_len__u16)
  {
    FLEA_THROW("encrypted premaster secret too long", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  // read encrypted premaster secret
  FLEA_ALLOC_BUF(enc_premaster_secret__bu8, enc_premaster_secret_len__u32);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      enc_premaster_secret__bu8,
      enc_premaster_secret_len__u32
    )
  );

  FLEA_CCALL(
    THR_flea_pk_api__decrypt_message(
      flea_rsa_pkcs1_v1_5_encr,
      0, // we don't use a hash
      enc_premaster_secret__bu8,
      enc_premaster_secret_len__u32,
      premaster_secret__pt,
      tls_ctx->private_key__pt,
      48
    )
  );


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(enc_premaster_secret__bu8);
    // flea_private_key_t__dtor(&key__t);
  );
} /* THR_flea_tls__read_client_key_exchange_rsa */

# endif /* ifdef FLEA_HAVE_RSA */


# ifdef FLEA_HAVE_ECKA
static flea_err_t THR_flea_tls__read_client_key_exchange_ecdhe(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_byte_vec_t*          premaster_secret__pt,
  flea_private_key_t*       ecdhe_priv_key__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_public_key_t ecdhe_client_key__t = flea_public_key_t__INIT_VALUE;

  FLEA_THR_BEG_FUNC();

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  FLEA_CCALL(
    THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret(
      tls_ctx__pt,
      hs_rd_stream__pt,
      premaster_secret__pt,
      // &tls_ctx__pt->ecdhe_priv_key__t,
      ecdhe_priv_key__pt,
      &ecdhe_client_key__t
    )
  );

  FLEA_THR_FIN_SEC(
    flea_public_key_t__dtor(&ecdhe_client_key__t);
    /* we can destroy the object since we don't need it later: */
    flea_private_key_t__dtor(ecdhe_priv_key__pt);
  );
} /* THR_flea_tls__read_client_key_exchange_ecdhe */

# endif /* ifdef FLEA_HAVE_ECKA */

static flea_err_t THR_flea_tls__read_client_key_exchange(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_byte_vec_t*          premaster_secret__pt,
  flea_private_key_t*       ecdhe_priv_key__pt
)
{
  flea_tls__kex_method_t kex_method__t;

  FLEA_THR_BEG_FUNC();
  kex_method__t = flea_tls_get_kex_method_by_cipher_suite_id(tls_ctx->selected_cipher_suite__u16);
  if(kex_method__t == FLEA_TLS_KEX_RSA)
  {
# ifdef FLEA_HAVE_RSA
    FLEA_CCALL(THR_flea_tls__read_client_key_exchange_rsa(tls_ctx, hs_rdr__pt, premaster_secret__pt));
# else
    // should not happen if everything is properly configured
    FLEA_THROW("unsupported key exchange variant", FLEA_ERR_TLS_INVALID_STATE);
# endif
  }
  else if(kex_method__t == FLEA_TLS_KEX_ECDHE)
  {
# ifdef FLEA_HAVE_ECKA
    FLEA_CCALL(
      THR_flea_tls__read_client_key_exchange_ecdhe(
        tls_ctx,
        hs_rdr__pt,
        premaster_secret__pt,
        ecdhe_priv_key__pt
      )
    );
# else
    // should not happen if everything is properly configured
    FLEA_THROW("unsupported key exchange variant", FLEA_ERR_TLS_INVALID_STATE);
# endif /* ifdef FLEA_HAVE_ECKA */
  }
  else
  {
    // should not happen
    FLEA_THROW("unsupported key exchange variant", FLEA_ERR_TLS_INVALID_STATE);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_client_key_exchange */

static flea_err_t THR_flea_tls__read_cert_verify(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_handsh_reader_t*     hs_rdr__pt,
  flea_hash_ctx_t*              hash_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_public_key_t*            peer_public_key__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u8_t sig_hash_alg__au8[2];
  flea_u8_t sig_len_to_dec__au8[2];
  flea_u16_t sig_len__u16;

  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_DECL_BUF(sig__bu8, flea_u8_t, FLEA_MAX_SIG_SIZE);

  flea_hash_id_t hash_id__t;
  flea_pk_scheme_id_t pk_scheme_id__t;
  flea_u16_t hash_len__u8;

  flea_bool_t check__b;

  FLEA_THR_BEG_FUNC();

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  // read sig and hash algorithm
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      sig_hash_alg__au8,
      2
    )
  );

  // read signature length
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      sig_len_to_dec__au8,
      2
    )
  );
  sig_len__u16 = flea__decode_U16_BE(sig_len_to_dec__au8);

  // read signature
  FLEA_ALLOC_BUF(sig__bu8, sig_len__u16);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      sig__bu8,
      sig_len__u16
    )
  );

  FLEA_CCALL(THR_flea_tls__map_tls_hash_to_flea_hash(sig_hash_alg__au8[0], &hash_id__t));
  FLEA_CCALL(THR_flea_tls__map_tls_sig_to_flea_sig(sig_hash_alg__au8[1], &pk_scheme_id__t));

  // check that we support the combination of hash/sig alg and the client has
  // indeed responded with a combination that we offered
  check__b = FLEA_FALSE;
  for(flea_al_u16_t i = 0; i < tls_ctx->allowed_sig_algs__rcu8.len__dtl; i += 2)
  {
    if((flea_hash_id_t) tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i] == hash_id__t &&
      (flea_pk_scheme_id_t) tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i + 1] == pk_scheme_id__t)
    {
      check__b = FLEA_TRUE;
    }
  }
  if(check__b == FLEA_FALSE)
  {
    FLEA_THROW("Client didn't respond with a valid signature algorithm pair", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

  hash_len__u8 = flea_hash__get_output_length_by_id(hash_id__t);

  // check if we use the PRF hash function (copy is in hash_ctx) or one of the
  // functions in the p_hash_ctx
  FLEA_ALLOC_BUF(messages_hash__bu8, hash_len__u8);
  if(hash_id__t == flea_hash_ctx_t__get_hash_id(hash_ctx))
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx, messages_hash__bu8));
  }
  else
  {
    FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__final(p_hash_ctx__pt, hash_id__t, FLEA_FALSE, messages_hash__bu8));
  }

  FLEA_CCALL(
    THR_flea_public_key_t__verify_digest_plain_format(
      // &tls_ctx->peer_pubkey,
      peer_public_key__pt,
      pk_scheme_id__t,
      hash_id__t,
      messages_hash__bu8,
      hash_len__u8,
      sig__bu8,
      sig_len__u16
    )
  );


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(messages_hash__bu8);
    FLEA_FREE_BUF_FINAL(sig__bu8);
  );
} /* THR_flea_tls__read_cert_verify */

static flea_err_t THR_flea_tls_server_handle_handsh_msg(
  flea_tls_server_ctx_t*        server_ctx__pt,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls__handshake_state_t*  handshake_state,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_byte_vec_t*              premaster_secret__pt,
  flea_public_key_t*            peer_public_key__pt,
  flea_private_key_t*           ecdhe_priv_key__pt
)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  FLEA_DECL_OBJ(hash_ctx_copy__t, flea_hash_ctx_t);
  flea_hash_id_t hash_id__t;

  flea_tls_ctx_t* tls_ctx = &server_ctx__pt->tls_ctx__t;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx->rec_prot__t));
  if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED ||
    flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
  {
    /*
     * for read_finished use a copy of hash_ctx where the finished message is not included yet
     * same for certificate verify message but use the appropriate hash function
     * instead of PRF hash
     */
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
    {
      // stop hashing for all functions but the one for PRF which is the only
      // one we will need in the following messages
      flea_tls_parallel_hash_ctx_t__stop_update_for_all_but_one(
        p_hash_ctx__pt,
        flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__u16)
      );
    }
    hash_id__t = flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__u16);
    FLEA_CCALL(
      THR_flea_tls_parallel_hash_ctx_t__create_hash_ctx_as_copy(
        &hash_ctx_copy__t,
        p_hash_ctx__pt,
        hash_id__t
      )
    );
  }
  FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, p_hash_ctx__pt));


  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CLIENT_HELLO)
    {
      FLEA_CCALL(THR_flea_tls__read_client_hello(server_ctx__pt, hs_ctx__pt, &handsh_rdr__t));
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      FLEA_THR_RETURN();
    }
    else
    {
      FLEA_THROW("Unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }

  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
  {
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE;
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE)
    {
      // base allowed cl_certs on allowed signature algorithms
      flea_u8_t cert_mask__u8 = 0;
      for(flea_u8_t i = 1; i < tls_ctx->allowed_sig_algs__rcu8.len__dtl; i += 2)
      {
        if(tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i] == flea_rsa_pkcs1_v1_5_sign)
        {
          cert_mask__u8 |= flea_tls_cl_cert__rsa_sign;
        }
        else if(tls_ctx->allowed_sig_algs__rcu8.data__pcu8[i] == flea_ecdsa_emsa1)
        {
          cert_mask__u8 |= flea_tls_cl_cert__ecdsa_sign;
        }
      }
      flea_tls_cert_path_params_t cert_path_params__t =
      {.kex_type__e                  =               0,
       .client_cert_type_mask__u8    = cert_mask__u8,
       .validate_server_or_client__e = FLEA_TLS_CLIENT,
       .hostn_valid_params__pt       = NULL};

      FLEA_CCALL(
        THR_flea_tls__read_certificate(
          tls_ctx,
          &handsh_rdr__t,
          // &tls_ctx->peer_pubkey,
          peer_public_key__pt,
          &cert_path_params__t
        )
      );
      FLEA_THR_RETURN();
    }
  }
  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE)
  {
    if(handshake_state->send_client_cert == FLEA_TRUE)
    {
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY;
    }
    else
    {
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
    }
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE)
    {
      FLEA_CCALL(
        THR_flea_tls__read_client_key_exchange(
          tls_ctx,
          &handsh_rdr__t,
          premaster_secret__pt,
          ecdhe_priv_key__pt
        )
      );
      FLEA_THR_RETURN();
    }
  }

  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY)
  {
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;

    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
    {
      FLEA_CCALL(
        THR_flea_tls__read_cert_verify(
          tls_ctx,
          &handsh_rdr__t,
          &hash_ctx_copy__t,
          p_hash_ctx__pt,
          peer_public_key__pt
        )
      );
      FLEA_THR_RETURN();
    }
  }

  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
  {
    if(!server_ctx__pt->server_resume_session__u8)
    {
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
    }
    else
    {
      handshake_state->finished = FLEA_TRUE;
    }
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
    {
      FLEA_CCALL(THR_flea_tls__read_finished(tls_ctx, &handsh_rdr__t, &hash_ctx_copy__t));
      // FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, hash_ctx__pt));

      FLEA_THR_RETURN();
    }
    else
    {
      FLEA_THROW("Expected finished message, but got something else", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }

  FLEA_THROW("No handshake message processed", FLEA_ERR_TLS_INVALID_STATE);

  FLEA_THR_FIN_SEC(
    flea_tls_handsh_reader_t__dtor(&handsh_rdr__t);
    flea_hash_ctx_t__dtor(&hash_ctx_copy__t);
  );
} /* THR_flea_handle_handsh_msg */

flea_err_t THR_flea_tls__server_handshake(
  flea_tls_server_ctx_t* server_ctx__pt
)
{
  flea_tls_ctx_t* tls_ctx = &server_ctx__pt->tls_ctx__t;

# ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE;
# else
  flea_u8_t premaster_secret__au8[FLEA_MAX(48, FLEA_ECC_MAX_ENCODED_POINT_LEN)];
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_NOT_ALLOCATABLE(
    premaster_secret__au8,
    sizeof(premaster_secret__au8)
    );
# endif
  // TODO: KEY BLOCK SIZE #596
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(key_block__t, 256);
  flea_public_key_t peer_public_key__t;
  tls_ctx->extension_ctrl__u8 = 0;
  // define and init state
  flea_tls__handshake_state_t handshake_state;
  flea_private_key_t ecdhe_priv_key__t;
  flea_tls_handshake_ctx_t hs_ctx__t;

  flea_tls_parallel_hash_ctx_t p_hash_ctx;
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    client_and_server_random__t,
    2 * FLEA_TLS_HELLO_RANDOM_SIZE
  );
  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__begin_handshake(tls_ctx);
  hs_ctx__t.client_and_server_random__pt = &client_and_server_random__t;
  hs_ctx__t.tls_ctx__pt = tls_ctx;

  flea_public_key_t__INIT(&peer_public_key__t);
  flea_private_key_t__INIT(&ecdhe_priv_key__t);
  flea_tls_parallel_hash_ctx_t__INIT(&p_hash_ctx);
  flea_tls__handshake_state_ctor(&handshake_state);

  // TODO: make configurable #597
  flea_hash_id_t hash_ids[] = {flea_sha1, flea_sha224, flea_sha256, flea_sha384, flea_sha512};

  FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__ctor(&p_hash_ctx, hash_ids, FLEA_NB_ARRAY_ENTRIES(hash_ids)));

  FLEA_CCALL(THR_flea_byte_vec_t__resize(hs_ctx__t.client_and_server_random__pt, 2 * FLEA_TLS_HELLO_RANDOM_SIZE));

  FLEA_CCALL(
    THR_flea_rng__randomize(
      hs_ctx__t.client_and_server_random__pt->data__pu8,
      2 * FLEA_TLS_HELLO_RANDOM_SIZE
    )
  );
  // flea_tls_set_tls_random(&hs_ctx__t);
  // tls_ctx->server_active_sess_mbn__pt = NULL;
  server_ctx__pt->server_resume_session__u8 = 0;
  handshake_state.initialized       = FLEA_TRUE;
  handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO;
  if(tls_ctx->trust_store__pt->nb_set_certs__u16 == 0)
  {
    handshake_state.send_client_cert = FLEA_FALSE;
  }
  else
  {
    handshake_state.send_client_cert = FLEA_TRUE;
  }

  while(handshake_state.finished != FLEA_TRUE)
  {
    /*
     * read next record
     */
    if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_NONE)
    {
      ContentType cont_type__e;
      FLEA_CCALL(
        THR_flea_tls_rec_prot_t__get_current_record_type(
          &tls_ctx->rec_prot__t,
          &cont_type__e,
          flea_read_full
        )
      );

      if(cont_type__e == CONTENT_TYPE_HANDSHAKE)
      {
        FLEA_CCALL(
          THR_flea_tls_server_handle_handsh_msg(
            server_ctx__pt,
            &hs_ctx__t,
            &handshake_state,
            &p_hash_ctx,
            &premaster_secret__t,
            &peer_public_key__t,
            &ecdhe_priv_key__t
          )
        );
      }
      else if(cont_type__e == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(!(handshake_state.expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC))
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
        }
        else
        {
          flea_u8_t dummy_byte;
          flea_al_u16_t len_one__alu16 = 1;
          flea_al_u16_t key_block_len__alu16;

          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__read_data(
              &tls_ctx->rec_prot__t,
              CONTENT_TYPE_CHANGE_CIPHER_SPEC,
              &dummy_byte,
              &len_one__alu16,
              flea_read_full
            )
          );

          /*
           * Enable encryption for incoming messages
           */
          if(!server_ctx__pt->server_resume_session__u8)
          {
            // setup key material
            // TODO: only one arg:
            FLEA_CCALL(
              THR_flea_tls__create_master_secret(
                // tls_ctx->client_and_server_random__bu8,
                &hs_ctx__t,
                &premaster_secret__t,
                tls_ctx->master_secret__bu8,
                tls_ctx->selected_cipher_suite__u16
              )
            );

            /*if(tls_ctx->server_active_sess_mbn__pt)
             * {
             * memcpy(
             *  tls_ctx->server_active_sess_mbn__pt,
             *  tls_ctx->master_secret__bu8,
             *  FLEA_TLS_MASTER_SECRET_SIZE
             * );
             * tls_ctx->server_active_sess_mbn__pt->session__t.is_valid_session__u8 = 1;
             * tls_ctx->server_active_sess_mbn__pt->session__t.cipher_suite_id__u16 =
             *  tls_ctx->selected_cipher_suite__u16;
             * }*/

            memcpy(
              server_ctx__pt->active_session__t.session_data__t.master_secret__au8,
              tls_ctx->master_secret__bu8,
              FLEA_TLS_MASTER_SECRET_SIZE
            );
            // tls_ctx->server_active_sess_mbn__pt->session__t.is_valid_session__u8 = 1;

            /*tls_ctx->server_active_sess_mbn__pt->session__t.cipher_suite_id__u16 =
             * tls_ctx->selected_cipher_suite__u16;*/
            server_ctx__pt->active_session__t.session_data__t.cipher_suite_id__u16 =
              tls_ctx->selected_cipher_suite__u16;
          }
          FLEA_CCALL(
            THR_flea_tls_get_key_block_len_from_cipher_suite_id(
              (flea_tls__cipher_suite_id_t) tls_ctx->selected_cipher_suite__u16,
              &key_block_len__alu16
            )
          );
          FLEA_CCALL(THR_flea_byte_vec_t__resize(&key_block__t, key_block_len__alu16));
          FLEA_CCALL(
            THR_flea_tls__generate_key_block(
              &hs_ctx__t,
              tls_ctx->selected_cipher_suite__u16,
              // &tls_ctx->security_parameters,
              key_block__t.data__pu8,
              key_block_len__alu16
            )
          );

          // enable encryption for read direction
          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__set_ciphersuite(
              &tls_ctx->rec_prot__t,
              flea_tls_read,
              FLEA_TLS_SERVER,
              (flea_tls__cipher_suite_id_t) tls_ctx->selected_cipher_suite__u16,
              key_block__t.data__pu8
            )
          );
          if(server_ctx__pt->server_resume_session__u8)
          {
            flea_byte_vec_t__dtor(&key_block__t);
          }

          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;

          continue;
        }
      }
      else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
      }
    }
    // We don't expect another message so it's our turn to continue
    else
    {
      if(handshake_state.sent_first_round == FLEA_FALSE)
      {
        FLEA_CCALL(THR_flea_tls__send_server_hello(server_ctx__pt, &hs_ctx__t, &p_hash_ctx));
        if(!server_ctx__pt->server_resume_session__u8)
        {
          FLEA_CCALL(
            THR_flea_tls__send_certificate(
              tls_ctx,
              &p_hash_ctx,
              tls_ctx->cert_chain_mbn__pt,
              tls_ctx->cert_chain_len__u8
            )
          );


          // send server key exchange depending on cipher suite
          if(flea_tls_get_kex_method_by_cipher_suite_id(
              (flea_tls__cipher_suite_id_t) tls_ctx->
              selected_cipher_suite__u16
            ) == FLEA_TLS_KEX_ECDHE)
          {
            FLEA_CCALL(THR_flea_tls__send_server_kex(tls_ctx, &hs_ctx__t, &p_hash_ctx, &ecdhe_priv_key__t));
          }

          // send certificate request in case we want client authentication
          if(handshake_state.send_client_cert == FLEA_TRUE)
          {
            FLEA_CCALL(
              THR_flea_tls__send_cert_request(
                tls_ctx,
                &p_hash_ctx
              )
            );
          }

          FLEA_CCALL(
            THR_flea_tls__send_handshake_message(
              &tls_ctx->rec_prot__t,
              &p_hash_ctx,
              HANDSHAKE_TYPE_SERVER_HELLO_DONE,
              (flea_u8_t*) NULL,
              0
            )
          );

          handshake_state.sent_first_round = FLEA_TRUE;

          if(handshake_state.send_client_cert == FLEA_TRUE)
          {
            handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE;
          }
          else
          {
            handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE;
          }
        }
        else
        {
          /* session resumption */
          handshake_state.sent_first_round  = FLEA_TRUE;
          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
        }
      }
      else
      {
        FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx));
        if(server_ctx__pt->server_resume_session__u8)
        {
          flea_al_u16_t key_block_len__alu16;
          memcpy(
            tls_ctx->master_secret__bu8, // TODO: GET RID OF MASTER SECRET, USE THE ONE FROM THE ACTIVE SESSION
            // tls_ctx->server_active_sess_mbn__pt->session__t.master_secret__au8,
            server_ctx__pt->active_session__t.session_data__t.master_secret__au8,
            FLEA_TLS_MASTER_SECRET_SIZE
          );
          /* set up master secret and key block */
          FLEA_CCALL(
            THR_flea_tls_get_key_block_len_from_cipher_suite_id(
              tls_ctx->selected_cipher_suite__u16,
              &key_block_len__alu16
            )
          );
          FLEA_CCALL(THR_flea_byte_vec_t__resize(&key_block__t, key_block_len__alu16));
          FLEA_CCALL(
            THR_flea_tls__generate_key_block(
              &hs_ctx__t,
              tls_ctx->selected_cipher_suite__u16,
              key_block__t.data__pu8,
              key_block_len__alu16
            )
          );
        }
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__set_ciphersuite(
            &tls_ctx->rec_prot__t,
            flea_tls_write,
            FLEA_TLS_SERVER,
            tls_ctx->selected_cipher_suite__u16,
            key_block__t.data__pu8
          )
        );

        FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &p_hash_ctx));
        if(!server_ctx__pt->server_resume_session__u8)
        {
          handshake_state.finished = FLEA_TRUE;
          break;
        }
        else
        {
          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
        }
      }

      continue;
    }
  }
  if(server_ctx__pt->session_mngr_mbn__pt)
  {
    FLEA_CCALL(
      THR_flea_tls_session_mngr_t__store_session(
        server_ctx__pt->session_mngr_mbn__pt,
        &server_ctx__pt->active_session__t
      )
    );
  }
  FLEA_THR_FIN_SEC(
    flea_tls_parallel_hash_ctx_t__dtor(&p_hash_ctx);
    flea_byte_vec_t__dtor(&premaster_secret__t);
    flea_byte_vec_t__dtor(&key_block__t);
    flea_byte_vec_t__dtor(&client_and_server_random__t);
    flea_public_key_t__dtor(&peer_public_key__t);
    flea_private_key_t__dtor(&ecdhe_priv_key__t);
  );
} /* THR_flea_tls__server_handshake */

flea_err_t THR_flea_tls_server_ctx_t__read_app_data(
  flea_tls_server_ctx_t*  tls_server_ctx__pt,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
)
{
  return THR_flea_tls_ctx_t__read_app_data(
    tls_server_ctx__pt,
    NULL,
    data__pu8,
    data_len__palu16,
    rd_mode__e,
    NULL
  );
}

flea_err_t THR_flea_tls_server_ctx_t__ctor(
  flea_tls_server_ctx_t*        tls_server_ctx__pt,
  flea_tls_shared_server_ctx_t* shrd_server_ctx__pt,
  flea_rw_stream_t*             rw_stream__pt,
  const flea_ref_cu8_t*         cert_chain__pt,
  flea_al_u8_t                  cert_chain_len__alu8,
  const flea_cert_store_t*      trust_store__pt,
  const flea_ref_cu16_t*        allowed_cipher_suites__prcu16,
  const flea_byte_vec_t*        crl_der__pt,
  flea_al_u16_t                 nb_crls__alu16,
  flea_tls_session_mngr_t*      session_mngr_mbn__pt,
  flea_ref_cu8_t*               allowed_ecc_curves_ref__prcu8,
  flea_ref_cu8_t*               allowed_sig_algs_ref__prcu8,
  flea_al_u16_t                 flags__alu16
)
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t* tls_ctx__pt = &tls_server_ctx__pt->tls_ctx__t;
  tls_ctx__pt->cfg_flags__u16 = flags__alu16;
  tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16 = nb_crls__alu16;
  tls_ctx__pt->rev_chk_cfg__t.crl_der__pt  = crl_der__pt;
  tls_ctx__pt->cert_chain_mbn__pt       = cert_chain__pt;
  tls_ctx__pt->cert_chain_len__u8       = cert_chain_len__alu8;
  tls_ctx__pt->extension_ctrl__u8       = 0;
  tls_ctx__pt->allowed_ecc_curves__rcu8 = *allowed_ecc_curves_ref__prcu8;
  tls_ctx__pt->allowed_sig_algs__rcu8   = *allowed_sig_algs_ref__prcu8;
  tls_ctx__pt->private_key__pt = &shrd_server_ctx__pt->private_key__t;

  tls_ctx__pt->trust_store__pt = trust_store__pt;
  tls_ctx__pt->allowed_cipher_suites__prcu16 = allowed_cipher_suites__prcu16;
  tls_ctx__pt->connection_end              = FLEA_TLS_SERVER;
  tls_ctx__pt->client_session_mbn__pt      = NULL;
  tls_server_ctx__pt->session_mngr_mbn__pt = session_mngr_mbn__pt;

  FLEA_CCALL(THR_flea_tls_ctx_t__construction_helper(tls_ctx__pt, rw_stream__pt));
  err__t = THR_flea_tls__server_handshake(tls_server_ctx__pt);// , FLEA_FALSE);
  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_server_ctx__pt, NULL, err__t, FLEA_FALSE, FLEA_FALSE));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_server_ctx_t__renegotiate(
  flea_tls_server_ctx_t*   tls_server_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  const flea_ref_cu8_t*    cert_chain__pt, // TODO: if here a new cert chain can be specified, then also the private key needs to change => simply provide a new shared_server_ctx with all this information
  flea_al_u8_t             cert_chain_len__alu8,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  // flea_rev_chk_mode_e      rev_chk_mode__e,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
)
{
  return THR_flea_tls_ctx_t__renegotiate(
    tls_server_ctx__pt,
    NULL,
    trust_store__pt,
    cert_chain__pt,
    cert_chain_len__alu8,
    allowed_cipher_suites__prcu16,
    // rev_chk_mode__e,
    crl_der__pt,
    nb_crls__alu16,
    NULL
  );
}

void flea_tls_server_ctx_t__dtor(flea_tls_server_ctx_t* tls_server_ctx__pt)
{
  flea_tls_ctx_t__dtor(&tls_server_ctx__pt->tls_ctx__t);
}

flea_err_t THR_flea_tls_server_ctx_t__send_app_data(
  flea_tls_server_ctx_t* tls_server_ctx__pt,
  const flea_u8_t*       data,
  flea_u8_t              data_len
)
{
  return THR_flea_tls_ctx_t__send_app_data(tls_server_ctx__pt, NULL, data, data_len);
}

flea_err_t THR_flea_tls_server_ctx_t__flush_write_app_data(flea_tls_server_ctx_t* tls_server_ctx__pt)
{
  return THR_flea_tls_ctx_t__flush_write_app_data(&tls_server_ctx__pt->tls_ctx__t);
}

# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
flea_bool_t flea_tls_server_ctx_t__have_peer_ee_cert_ref(flea_tls_server_ctx_t* server_ctx__pt)
{
  return server_ctx__pt->tls_ctx__t.peer_ee_cert_data__t.len__dtl != 0;
}

const flea_x509_cert_ref_t* flea_tls_server_ctx_t__get_peer_ee_cert_ref(flea_tls_server_ctx_t* server_ctx__pt)
{
  if(flea_tls_server_ctx_t__have_peer_ee_cert_ref(server_ctx__pt))
  {
    return &server_ctx__pt->tls_ctx__t.peer_ee_cert_ref__t;
  }
  return NULL;
}

# endif /* ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF */

# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
flea_bool_t flea_tls_server_ctx_t__have_peer_root_cert_ref(flea_tls_server_ctx_t* server_ctx__pt)
{
  return server_ctx__pt->tls_ctx__t.peer_root_cert_set__u8;
}

const flea_x509_cert_ref_t* flea_tls_server_ctx_t__get_peer_root_cert_ref(flea_tls_server_ctx_t* server_ctx__pt)
{
  if(flea_tls_server_ctx_t__have_peer_root_cert_ref(server_ctx__pt))
  {
    return &server_ctx__pt->tls_ctx__t.peer_root_cert_ref__t;
  }
  return NULL;
}

# endif /* ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF */

#endif /* ifdef FLEA_HAVE_TLS */
