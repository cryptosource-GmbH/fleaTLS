/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/tls_session_mngr.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "flea/tls_client.h"
#include "flea/privkey.h"
#include "flea/cert_store.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"
#include "internal/common/tls/parallel_hash.h"
#include "internal/common/tls/tls_int.h"
#include "internal/common/tls/tls_client_int.h"
#include "flea/rng.h"
#include "flea/pk_api.h"
#include "flea/pkcs8.h"

#ifdef FLEA_HAVE_TLS

static flea_err_t THR_flea_tls__read_server_hello(
  flea_tls_ctx_t*            tls_ctx,
  flea_tls_handshake_ctx_t*  hs_ctx__pt,
  flea_tls_handsh_reader_t*  hs_rdr__pt,
  flea_tls_client_session_t* client_session_mbn__pt
)
{
  flea_u8_t server_compression_meth__u8;
  flea_u8_t server_version_major_minor__au8[2];
  flea_u8_t session_id_len__u8;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_u32_t cipher_suite__u32;
  flea_bool_t found_sec_reneg__b = FLEA_FALSE;

  // flea_u16_t cipher_suite_id__u16;

  FLEA_DECL_BUF(session_id__bu8, flea_u8_t, 32);
  const flea_al_u8_t max_session_id_len__alu8 = 32;
  FLEA_THR_BEG_FUNC();
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) < 41) /* min ServerHello length */
  {
    FLEA_THROW("length too small", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

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

  // read random
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      // tls_ctx->client_and_server_random__bu8 + FLEA_TLS_HELLO_RANDOM_SIZE,
      hs_ctx__pt->client_and_server_random__pt->data__pu8 + FLEA_TLS_HELLO_RANDOM_SIZE,
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


  if(client_session_mbn__pt)
  {
    FLEA_ALLOC_BUF(session_id__bu8, session_id_len__u8);
    client_session_mbn__pt->for_resumption__u8 = 0;
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        session_id__bu8,
        session_id_len__u8
      )
    );
    if(session_id_len__u8 && (0 ==
      flea_memcmp_wsize(
        client_session_mbn__pt->session_id__au8,
        client_session_mbn__pt->session_id_len__u8,
        session_id__bu8,
        session_id_len__u8
      )))
    {
      /* resumption case */
      client_session_mbn__pt->for_resumption__u8 = 1;
    }
    else
    {
      flea_tls_session_data_t__invalidate_session(&client_session_mbn__pt->session__t);
    }
    client_session_mbn__pt->session_id_len__u8 = session_id_len__u8;
    /* update the session id even if the the server sent one of length zero */
    memcpy(client_session_mbn__pt->session_id__au8, session_id__bu8, session_id_len__u8);
    client_session_mbn__pt->session_id_len__u8 = session_id_len__u8;
  }
  else
  {
    FLEA_CCALL(
      THR_flea_rw_stream_t__skip_read(
        hs_rd_stream__pt,
        session_id_len__u8
      )
    );
  }

  FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(hs_rd_stream__pt, &cipher_suite__u32, 2));
  tls_ctx->selected_cipher_suite__u16 = (flea_u16_t) cipher_suite__u32;


  if(!flea_is_in_u16_list(tls_ctx->selected_cipher_suite__u16, tls_ctx->allowed_cipher_suites__prcu16))
  {
    FLEA_THROW("invalid ciphersuite selected by peer", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      hs_rd_stream__pt,
      &server_compression_meth__u8
    )
  );
  if(server_compression_meth__u8 != NO_COMPRESSION)
  {
    FLEA_THROW("unsupported compression method from server", FLEA_ERR_TLS_INV_ALGO_IN_SERVER_HELLO);
  }

  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_CCALL(
      THR_flea_tls_ctx_t__parse_hello_extensions(
        tls_ctx,
        hs_rdr__pt,
        &found_sec_reneg__b,
        tls_ctx->private_key_for_client_mbn__pt
      )
    );
  }
  if(tls_ctx->sec_reneg_flag__u8 && !found_sec_reneg__b)
  {
    FLEA_THROW("missing renegotiation info in peer's extensions", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  if(found_sec_reneg__b)
  {
    tls_ctx->allow_insec_reneg__u8 = FLEA_FALSE;
    tls_ctx->sec_reneg_flag__u8    = FLEA_TRUE;
  }
  else if(tls_ctx->allow_insec_reneg__u8 == FLEA_FALSE)
  {
    tls_ctx->allow_reneg__u8 = FLEA_FALSE;
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(session_id__bu8);
  );
} /* THR_flea_tls__read_server_hello */

// TODO compile only if we support ecdh/ecdhe or any other cipher suites that
// use server key exchange message
static flea_err_t THR_flea_tls__read_server_kex(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_byte_vec_t*          premaster_secret__pt,
  flea_public_key_t*        peer_public_key__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_tls__kex_method_t kex_method__t;

  flea_u8_t ec_curve_type__u8;
  flea_u8_t ec_curve__au8[2];
  flea_ec_dom_par_id_t ec_dom_par_id__t;
  flea_ref_cu8_t server_pub_point__rcu8;


  flea_private_key_t ecdhe_priv_key__t  = flea_private_key_t__INIT_VALUE;
  flea_public_key_t ecdhe_server_key__t = flea_private_key_t__INIT_VALUE;

  flea_u8_t sig_and_hash_alg__au8[2];
  flea_u8_t sig_to_vfy_len_enc__au8[2];
  flea_u16_t sig_to_vfy_len__u16;
  flea_hash_id_t hash_id__t;
  flea_pk_scheme_id_t pk_scheme_id__t;
  flea_u8_t hash_out_len__u8;
  flea_u8_t i;
  flea_bool_t found__b = FLEA_FALSE;

  FLEA_DECL_OBJ(params_hash_ctx__t, flea_hash_ctx_t);
  FLEA_DECL_BUF(hash__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_DECL_BUF(sig_to_vfy__bu8, flea_u8_t, FLEA_MAX_SIG_SIZE);

  FLEA_THR_BEG_FUNC();


  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  kex_method__t    = flea_tls_get_kex_method_by_cipher_suite_id(tls_ctx__pt->selected_cipher_suite__u16);
  if(kex_method__t == FLEA_TLS_KEX_ECDHE)
  {
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_byte(
        hs_rd_stream__pt,
        &ec_curve_type__u8
      )
    );
    if(ec_curve_type__u8 != 0x03)
    {
      FLEA_THROW("unsupported curve type", FLEA_ERR_TLS_HANDSHK_FAILURE);
    }

    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        ec_curve__au8,
        sizeof(ec_curve__au8)
      )
    );

    FLEA_CCALL(THR_flea_tls__map_curve_bytes_to_flea_curve(ec_curve__au8, &ec_dom_par_id__t));

    tls_ctx__pt->chosen_ecc_dp_internal_id__u8 = (flea_u8_t) ec_dom_par_id__t;
    for(i = 0; i < tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl; i++)
    {
      if(ec_dom_par_id__t == tls_ctx__pt->allowed_ecc_curves__rcu8.data__pcu8[i])
      {
        found__b = FLEA_TRUE;
        break;
      }
    }
    if(!found__b)
    {
      FLEA_THROW("curve chosen by server is not supported or not configured", FLEA_ERR_TLS_HANDSHK_FAILURE);
    }

    FLEA_CCALL(THR_flea_tls__create_ecdhe_key(&ecdhe_priv_key__t, hs_ctx__pt->ecdhe_pub_key__pt, ec_dom_par_id__t));

    FLEA_CCALL(
      THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret(
        tls_ctx__pt,
        hs_rd_stream__pt,
        premaster_secret__pt,
        &ecdhe_priv_key__t,
        &ecdhe_server_key__t
      )
    );

    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        sig_and_hash_alg__au8,
        sizeof(sig_and_hash_alg__au8)
      )
    );

    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        sig_to_vfy_len_enc__au8,
        sizeof(sig_to_vfy_len_enc__au8)
      )
    );

    sig_to_vfy_len__u16 = flea__decode_U16_BE(sig_to_vfy_len_enc__au8);
    if(sig_to_vfy_len__u16 > FLEA_MAX_SIG_SIZE)
    {
      FLEA_THROW("Signature too large for current flea config", FLEA_ERR_TLS_HANDSHK_FAILURE);
    }
    FLEA_ALLOC_BUF(sig_to_vfy__bu8, sig_to_vfy_len__u16);

    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        sig_to_vfy__bu8,
        sig_to_vfy_len__u16
      )
    );

    /* verify signature */
    FLEA_CCALL(THR_flea_tls__map_tls_hash_to_flea_hash(sig_and_hash_alg__au8[0], &hash_id__t));
    FLEA_CCALL(THR_flea_tls__map_tls_sig_to_flea_sig(sig_and_hash_alg__au8[1], &pk_scheme_id__t));

    // check if pk_scheme_id__t and tls_ctx->peer_pubkey are compatible
    FLEA_CCALL(
      THR_flea_tls__check_sig_alg_compatibility_for_key_type(
        // tls_ctx__pt->peer_pubkey.key_type__t,
        peer_public_key__pt->key_type__t,
        pk_scheme_id__t
      )
    );

    // calculate hash of ec params
    FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&params_hash_ctx__t, hash_id__t));
    server_pub_point__rcu8 = flea_public_key__get_encoded_public_component(&ecdhe_server_key__t);
    FLEA_CCALL(
      THR_flea_hash_ctx_t__update(
        &params_hash_ctx__t,
        // tls_ctx__pt->client_and_server_random__bu8,
        hs_ctx__pt->client_and_server_random__pt->data__pu8,
        2 * FLEA_TLS_HELLO_RANDOM_SIZE
      )
    );
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, &ec_curve_type__u8, 1));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, ec_curve__au8, sizeof(ec_curve__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, (flea_u8_t*) &server_pub_point__rcu8.len__dtl, 1));
    FLEA_CCALL(
      THR_flea_hash_ctx_t__update(
        &params_hash_ctx__t,
        server_pub_point__rcu8.data__pcu8,
        server_pub_point__rcu8.len__dtl
      )
    );


    hash_out_len__u8 = flea_hash_ctx_t__get_output_length(&params_hash_ctx__t);
    FLEA_ALLOC_BUF(hash__bu8, hash_out_len__u8);
    FLEA_CCALL(THR_flea_hash_ctx_t__final(&params_hash_ctx__t, hash__bu8));

    // verify if signature matches the calculated hash
    FLEA_CCALL(
      THR_flea_public_key_t__verify_digest_plain_format(
        // &tls_ctx__pt->peer_pubkey,
        peer_public_key__pt,
        pk_scheme_id__t,
        hash_id__t,
        hash__bu8,
        hash_out_len__u8,
        sig_to_vfy__bu8,
        sig_to_vfy_len__u16
      )
    );
  }
  else
  {
    // should never come this far if we don't support the cipher suite / kex
    FLEA_THROW("Invalid state", FLEA_ERR_TLS_INVALID_STATE);
  }

  FLEA_THR_FIN_SEC(
    flea_private_key_t__dtor(&ecdhe_priv_key__t);
    flea_public_key_t__dtor(&ecdhe_server_key__t);
    FLEA_FREE_BUF_FINAL(sig_to_vfy__bu8);
    FLEA_FREE_BUF_FINAL(hash__bu8);
    flea_hash_ctx_t__dtor(&params_hash_ctx__t);
  );
} /* THR_flea_tls__read_server_kex */

static flea_err_t THR_flea_tls__send_client_hello(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_tls_client_session_t*    session_mbn__pt
)
{
  flea_al_u16_t i;
  flea_u32_t len;
  flea_al_u16_t ext_len__alu16;
  flea_u8_t version__au8[2];

  FLEA_THR_BEG_FUNC();

  tls_ctx->extension_ctrl__u8 = 0;
  for(i = 0; i < tls_ctx->allowed_cipher_suites__prcu16->len__dtl; i++)
  {
    if(flea_tls__is_cipher_suite_ecc_suite(tls_ctx->allowed_cipher_suites__prcu16->data__pcu16[i]))
    {
      tls_ctx->extension_ctrl__u8 = FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS | FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES;
    }
  }
  ext_len__alu16 = flea_tls_ctx_t__compute_extensions_length(tls_ctx);

  len = 2 + 1 + 0 + 32 + 2 + 2 * tls_ctx->allowed_cipher_suites__prcu16->len__dtl + 1 + 1 + 0 + ext_len__alu16;

  if(ext_len__alu16)
  {
    /* extension length field */
    len += 2;
  }
  if(session_mbn__pt && flea_tls_session_data_t__is_valid_session(&session_mbn__pt->session__t))
  {
    len += session_mbn__pt->session_id_len__u8;
  }

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CLIENT_HELLO,
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

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      // tls_ctx->client_and_server_random__bu8,
      hs_ctx__pt->client_and_server_random__pt->data__pu8,
      FLEA_TLS_HELLO_RANDOM_SIZE
    )
  );

  if(session_mbn__pt && flea_tls_session_data_t__is_valid_session(&session_mbn__pt->session__t))
  {
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_int_be(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        session_mbn__pt->session_id_len__u8,
        1
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        session_mbn__pt->session_id__au8,
        session_mbn__pt->session_id_len__u8
      )
    );
  }
  else
  {
    FLEA_CCALL(THR_flea_tls__send_handshake_message_int_be(&tls_ctx->rec_prot__t, p_hash_ctx, 0, 1));
    if(session_mbn__pt)
    {
      session_mbn__pt->session_id_len__u8 = 0;
    }
  }

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
    /*if(flea_tls__is_cipher_suite_ecc_suite(tls_ctx->allowed_cipher_suites__prcu16->data__pcu16[i]))
     * {
     * have_ecc_suites__b = FLEA_TRUE;
     * }*/
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
  // reusing version__au8 array
  version__au8[0] = 1;
  version__au8[1] = 0;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, version__au8, 2));

  // send extensions
  FLEA_CCALL(THR_flea_tls_ctx_t__send_extensions_length(tls_ctx, p_hash_ctx));
  FLEA_CCALL(THR_flea_tls_ctx_t__send_reneg_ext(tls_ctx, p_hash_ctx));
  FLEA_CCALL(THR_flea_tls_ctx_t__send_sig_alg_ext(tls_ctx, p_hash_ctx));

  /**
   * both ECC extensions are set or none, so it's sufficient to check one
   */
  if(tls_ctx->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS)
  {
    FLEA_CCALL(THR_flea_tls_ctx_t__send_ecc_point_format_ext(tls_ctx, p_hash_ctx));
    FLEA_CCALL(THR_flea_tls_ctx_t__send_ecc_supported_curves_ext(tls_ctx, p_hash_ctx));
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_client_hello */

static flea_err_t THR_flea_tls__read_cert_request(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt
)
{
  flea_rw_stream_t* hs_rd_stream__pt;

  flea_u8_t cert_types_len__u8;
  flea_u8_t sig_algs_len_to_dec__au8[2];
  flea_u16_t sig_algs_len__u16;
  flea_u8_t cert_authorities_len_to_dec__au8[2];
  flea_u16_t cert_authorities_len__u16;
  flea_u8_t curr_cert_type__u8;
  flea_bool_t found_cert_type__b;

  FLEA_THR_BEG_FUNC();
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  if(tls_ctx__pt->private_key_for_client_mbn__pt == NULL)
  {
    FLEA_CCALL(
      THR_flea_rw_stream_t__skip_read(
        hs_rd_stream__pt,
        flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt)
      )
    );
    FLEA_THR_RETURN();
  }

  // read certificate types field
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      hs_rd_stream__pt,
      &cert_types_len__u8
    )
  );

  found_cert_type__b = FLEA_FALSE;
  while(cert_types_len__u8--)
  {
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_byte(
        hs_rd_stream__pt,
        &curr_cert_type__u8
      )
    );

    // if(flea_tls__get_tls_cert_type_from_flea_key_type(tls_ctx__pt->private_key__t.key_type__t) == curr_cert_type__u8)
    if(flea_tls__get_tls_cert_type_from_flea_key_type(tls_ctx__pt->private_key_for_client_mbn__pt->key_type__t) ==
      curr_cert_type__u8)
    {
      found_cert_type__b = FLEA_TRUE;
    }
  }
  if(found_cert_type__b == FLEA_FALSE)
  {
    FLEA_THROW("server request's a certificate type that we can't provide", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

  // read signature algorithms length field
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      sig_algs_len_to_dec__au8,
      2
    )
  );
  // check length
  sig_algs_len__u16 = flea__decode_U16_BE(sig_algs_len_to_dec__au8);
  if(sig_algs_len__u16 % 2 != 0)
  {
    FLEA_THROW("Incorrect length for signature algorithms", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  FLEA_CCALL(
    THR_flea_tls__read_sig_algs_field_and_find_best_match(
      tls_ctx__pt,
      hs_rd_stream__pt,
      sig_algs_len__u16,
      tls_ctx__pt->private_key_for_client_mbn__pt
    )
  );


  // read certificate authorities field
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      cert_authorities_len_to_dec__au8,
      2
    )
  );
  cert_authorities_len__u16 = flea__decode_U16_BE(cert_authorities_len_to_dec__au8);

  // TODO: parse this, but currently it's not really useful if we only support
  // one certificate anyway. Send our certificate and hope that the server will accept it.
  FLEA_CCALL(THR_flea_rw_stream_t__skip_read(hs_rd_stream__pt, cert_authorities_len__u16));

  // check that there are no byes left
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("trailing bytes in certificate request message", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_cert_request */

static flea_err_t THR_flea_tls__send_client_key_exchange_ecdhe(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_byte_vec_t*              premaster_secret__pt
)
{
  flea_ref_cu8_t pub_point__rcu8;
  flea_u32_t hdr_len__u32;

  FLEA_THR_BEG_FUNC();


  pub_point__rcu8 = flea_public_key__get_encoded_public_component(hs_ctx__pt->ecdhe_pub_key__pt);
  hdr_len__u32    = pub_point__rcu8.len__dtl + 1;


  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      hdr_len__u32
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


  FLEA_THR_FIN_SEC(
    flea_public_key_t__dtor(hs_ctx__pt->ecdhe_pub_key__pt);
  );
} /* THR_flea_tls__send_client_key_exchange_ecdhe */

static flea_err_t THR_flea_tls__send_client_key_exchange_rsa(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_public_key_t*            pubkey,
  flea_byte_vec_t*              premaster_secret__pt
)
{
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(encrypted__t, FLEA_RSA_MAX_MOD_BYTE_LEN);
  flea_u8_t len_enc[2];
  const flea_u32_t premaster_secret_len = 48;

  FLEA_THR_BEG_FUNC();

  // first 2 bytes are version, following 46 random
  FLEA_CCALL(THR_flea_byte_vec_t__resize(premaster_secret__pt, premaster_secret_len));
  premaster_secret__pt->data__pu8[0] = tls_ctx->version.major;
  premaster_secret__pt->data__pu8[1] = tls_ctx->version.minor;

  // the last 46 bytes are random
  FLEA_CCALL(THR_flea_rng__randomize(premaster_secret__pt->data__pu8 + 2, premaster_secret_len - 2));

  FLEA_CCALL(
    THR_flea_public_key_t__encrypt_message(
      pubkey,
      flea_rsa_pkcs1_v1_5_encr,
      (flea_hash_id_t) 0, /* we don't use a hash */
      premaster_secret__pt->data__pu8,
      premaster_secret_len,
      &encrypted__t
    )
  );

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
  // flea_tls_ctx_t*               tls_ctx,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_public_key_t*            pubkey_mbn__pt,
  flea_byte_vec_t*              premaster_secret__pt
)
{
  flea_tls__kex_method_t kex_method__t;
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  FLEA_THR_BEG_FUNC();


  kex_method__t = flea_tls_get_kex_method_by_cipher_suite_id(tls_ctx__pt->selected_cipher_suite__u16);
  if(kex_method__t == FLEA_TLS_KEX_RSA)
  {
# ifdef FLEA_HAVE_RSA
    FLEA_CCALL(
      THR_flea_tls__send_client_key_exchange_rsa(
        tls_ctx__pt,
        p_hash_ctx,
        pubkey_mbn__pt,
        premaster_secret__pt
      )
    );
# else
    // should not happen if everything is properly configured
    FLEA_THROW("unsupported key exchange variant", FLEA_ERR_TLS_INVALID_STATE);
# endif /* ifdef FLEA_HAVE_RSA */
  }
  else if(kex_method__t == FLEA_TLS_KEX_ECDHE)
  {
# ifdef FLEA_HAVE_ECKA
    FLEA_CCALL(THR_flea_tls__send_client_key_exchange_ecdhe(tls_ctx__pt, hs_ctx__pt, p_hash_ctx, premaster_secret__pt));
# else
    // should not happen if everything is properly configured
    FLEA_THROW("unsupported key exchange variant", FLEA_ERR_TLS_INVALID_STATE);
# endif
  }
  else
  {
    // should not happen
    FLEA_THROW("unsupported key exchange variant", FLEA_ERR_TLS_INVALID_STATE);
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_client_key_exchange */

static flea_err_t THR_flea_tls__send_cert_verify(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx
)
{
  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  flea_u32_t hdr_len__u32;
  flea_u8_t sig_len_enc__u8[2];
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(message_vec__t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(sig_vec__t, FLEA_PK_MAX_SIGNATURE_LEN);
  flea_u8_t hash_len__u8;
  flea_u8_t hash_alg_enc__u8;
  flea_u8_t sig_alg_enc__u8;
  flea_pk_scheme_id_t pk_scheme_id__t;

  FLEA_THR_BEG_FUNC();

  hash_len__u8 = flea_hash__get_output_length_by_id(tls_ctx->chosen_hash_algorithm__t);
  FLEA_ALLOC_BUF(messages_hash__bu8, hash_len__u8);

  pk_scheme_id__t = flea_tls__get_sig_alg_from_key_type(tls_ctx->private_key_for_client_mbn__pt->key_type__t);

  FLEA_CCALL(
    THR_flea_tls_parallel_hash_ctx_t__final(
      p_hash_ctx,
      tls_ctx->chosen_hash_algorithm__t,
      FLEA_TRUE,
      messages_hash__bu8
    )
  );

  // digitally sign the messages hash
  FLEA_CCALL(
    THR_flea_byte_vec_t__set_content(
      &message_vec__t,
      messages_hash__bu8,
      hash_len__u8
    )
  );

  FLEA_CCALL(
    THR_flea_private_key_t__sign_digest_plain_format(
      tls_ctx->private_key_for_client_mbn__pt,
      pk_scheme_id__t,
      tls_ctx->chosen_hash_algorithm__t,
      messages_hash__bu8,
      hash_len__u8,
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
  FLEA_CCALL(THR_flea_tls__map_flea_hash_to_tls_hash(tls_ctx->chosen_hash_algorithm__t, &hash_alg_enc__u8));
  FLEA_CCALL(THR_flea_tls__map_flea_sig_to_tls_sig(pk_scheme_id__t, &sig_alg_enc__u8));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, &hash_alg_enc__u8, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, p_hash_ctx, &sig_alg_enc__u8, 1));

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
    FLEA_FREE_BUF_FINAL(messages_hash__bu8);
    flea_byte_vec_t__dtor(&message_vec__t);
    flea_byte_vec_t__dtor(&sig_vec__t);
  );
} /* THR_flea_tls__send_cert_verify */

static flea_err_t THR_flea_handle_handsh_msg(
  flea_tls_ctx_t*                       tls_ctx,
  flea_tls_handshake_ctx_t*             hs_ctx__pt,
  flea_tls__handshake_state_t*          handshake_state,
  flea_tls_parallel_hash_ctx_t*         p_hash_ctx__pt,
  flea_tls_client_session_t*            client_session_mbn__pt,
  flea_byte_vec_t*                      premaster_secret__pt,
  flea_public_key_t*                    peer_public_key__pt,
  const flea_hostn_validation_params_t* hostn_valid_params__pt
)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  FLEA_DECL_OBJ(hash_ctx_copy__t, flea_hash_ctx_t);

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx->rec_prot__t));
  // TODO: THESE CONDITIONS SHOULD BE RELAXABLE, SHOULD BE REMOVABLE COMPLETELY,
  // i.e. always add the hash-ctx:

  if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
  {
    FLEA_CCALL(
      THR_flea_tls_parallel_hash_ctx_t__create_hash_ctx_as_copy(
        &hash_ctx_copy__t,
        p_hash_ctx__pt,
        flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__u16)
      )
    );
  }
  if((flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) != HANDSHAKE_TYPE_FINISHED) ||
    (client_session_mbn__pt && client_session_mbn__pt->for_resumption__u8)
  )
  {
    FLEA_CCALL(THR_flea_tls_handsh_reader_t__set_hash_ctx(&handsh_rdr__t, p_hash_ctx__pt));
  }
  if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_HELLO)
    {
      FLEA_CCALL(THR_flea_tls__read_server_hello(tls_ctx, hs_ctx__pt, &handsh_rdr__t, client_session_mbn__pt));
      if(client_session_mbn__pt && client_session_mbn__pt->for_resumption__u8)
      {
        handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
      }
      else
      {
        handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE
          | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
 // | FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST // only enable this
 // after the server sent his certificate because only authenticated
 // servers can ask for client authentication
          | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
      }
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE &&
    flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE)
  {
    flea_tls_cert_path_params_t cert_path_params__t =
    {.kex_type__e                  = flea_tls__get_kex_and_auth_method_by_cipher_suite_id(
       tls_ctx->selected_cipher_suite__u16
       ), .client_cert_type_mask__u8=                    0,
     .validate_server_or_client__e = FLEA_TLS_SERVER,
     // .hostn_valid_params__pt       = &tls_ctx->hostn_valid_params__t};
     .hostn_valid_params__pt       = hostn_valid_params__pt};
    FLEA_CCALL(
      THR_flea_tls__read_certificate(
        tls_ctx,
        &handsh_rdr__t,
        // &tls_ctx->peer_pubkey,
        peer_public_key__pt,
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
    FLEA_CCALL(
      THR_flea_tls__read_server_kex(
        tls_ctx,
        hs_ctx__pt,
        &handsh_rdr__t,
        premaster_secret__pt,
        peer_public_key__pt
      )
    );
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
      | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST &&
    flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_CERTIFICATE_REQUEST)
  {
    /*if(tls_ctx->cert_chain_mbn__pt == NULL)
     * {
     * FLEA_THROW("Server requested a certificate but client has none", FLEA_ERR_TLS_HANDSHK_FAILURE);
     * }*/

    FLEA_CCALL(THR_flea_tls__read_cert_request(tls_ctx, &handsh_rdr__t));
    handshake_state->send_client_cert  = FLEA_TRUE;
    handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
  }
  else if(handshake_state->expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_SERVER_HELLO_DONE)
    {
      handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      // nothing to process
    }
    else
    {
      FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
    }
  }
  else if(handshake_state->expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
  {
    if(flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t) == HANDSHAKE_TYPE_FINISHED)
    {
      FLEA_CCALL(THR_flea_tls__read_finished(tls_ctx, &handsh_rdr__t, &hash_ctx_copy__t));
      if(client_session_mbn__pt && client_session_mbn__pt->for_resumption__u8)
      {
        handshake_state->expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      }
      else
      {
        handshake_state->finished = FLEA_TRUE;
      }
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

  // check if we processed all trailing bytes
  if(flea_tls_handsh_reader_t__get_msg_rem_len(&handsh_rdr__t) != 0)
  {
    FLEA_THROW("Malformed message: trailing bytes left", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&hash_ctx_copy__t);
    flea_tls_handsh_reader_t__dtor(&handsh_rdr__t);
  );
} /* THR_flea_handle_handsh_msg */

flea_err_t THR_flea_tls__client_handshake(
  flea_tls_ctx_t*                       tls_ctx,
  flea_tls_client_session_t*            session_mbn__pt,
  const flea_hostn_validation_params_t* hostn_valid_params__pt
)
{
  flea_tls__handshake_state_t handshake_state;
  flea_public_key_t ecdhe_pub_key__t;
  flea_tls_handshake_ctx_t hs_ctx__t;

  // TODO: KEY BLOCK SIZE #596
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(key_block__t, 256);

  flea_public_key_t peer_public_key__t;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    client_and_server_random__t,
    2 * FLEA_TLS_HELLO_RANDOM_SIZE
  );
  FLEA_THR_BEG_FUNC();

  flea_tls_ctx_t__begin_handshake(tls_ctx);
  hs_ctx__t.tls_ctx__pt = tls_ctx;
  hs_ctx__t.client_and_server_random__pt = &client_and_server_random__t;
  flea_public_key_t__INIT(&ecdhe_pub_key__t);
  hs_ctx__t.ecdhe_pub_key__pt = &ecdhe_pub_key__t;
  // define and init state

  flea_tls__handshake_state_ctor(&handshake_state);
  flea_public_key_t__INIT(&peer_public_key__t);
  flea_tls_parallel_hash_ctx_t p_hash_ctx;
# ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE;
# else
  flea_u8_t premaster_secret__au8[FLEA_MAX(48, FLEA_ECC_MAX_ENCODED_POINT_LEN)];
  flea_byte_vec_t premaster_secret__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_NOT_ALLOCATABLE(
    premaster_secret__au8,
    sizeof(premaster_secret__au8)
    );
# endif
  flea_tls_parallel_hash_ctx_t__INIT(&p_hash_ctx);

  tls_ctx->extension_ctrl__u8 = 0;

  /** TODO (FS): lass uns besprechen was die Kriterien für die Hash-Funktionen
   * sind, die hier unterstützt werden müssen. Dann sehen wir, wie wir die Menge
   * ableiten können.
   */
  flea_hash_id_t hash_ids[] = {flea_sha256, flea_sha1, flea_sha384}; // TODO 123: not hardcoded!!!!!

  FLEA_CCALL(THR_flea_byte_vec_t__resize(hs_ctx__t.client_and_server_random__pt, 2 * FLEA_TLS_HELLO_RANDOM_SIZE));
  // flea_tls_set_tls_random(&hs_ctx__t);
  //
  FLEA_CCALL(
    THR_flea_rng__randomize(
      hs_ctx__t.client_and_server_random__pt->data__pu8,
      2 * FLEA_TLS_HELLO_RANDOM_SIZE
    )
  );
  FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__ctor(&p_hash_ctx, hash_ids, FLEA_NB_ARRAY_ENTRIES(hash_ids)));
  while(1)
  {
    // initialize handshake by sending CLIENT_HELLO
    if(handshake_state.initialized == FLEA_FALSE)
    {
      // send client hello
      FLEA_CCALL(THR_flea_tls__send_client_hello(tls_ctx, &hs_ctx__t, &p_hash_ctx, session_mbn__pt));
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
          THR_flea_handle_handsh_msg(
            tls_ctx,
            &hs_ctx__t,
            &handshake_state,
            &p_hash_ctx,
            session_mbn__pt,
            &premaster_secret__t,
            &peer_public_key__t,
            hostn_valid_params__pt
          )
        );
        if(handshake_state.finished == FLEA_TRUE)
        {
          break;
        }
        continue;
        //    TODO: CALL CTORS FOR ALL OBJECTS
        //    UPDATE(JR): still relevant?

        // exclude finished message because we must not have it in our hash computation
      }
      else if(cont_type__e == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
        }
        else
        {
          flea_u8_t dummy_byte;
          flea_al_u16_t len_one__alu16 = 1;

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

          if(session_mbn__pt && session_mbn__pt->for_resumption__u8)
          {
            flea_al_u16_t key_block_len__alu16;
            // TODO: REMOVE THAT ASSIGNEMENT, THAT MUST BE DONE CORRECTLY BY THE
            // SERVER / SET IN READ SERVER HELLO
            tls_ctx->selected_cipher_suite__u16 = session_mbn__pt->session__t.cipher_suite_id__u16;
            memcpy(
              tls_ctx->master_secret__bu8,
              session_mbn__pt->session__t.master_secret__au8,
              FLEA_TLS_MASTER_SECRET_SIZE
            );
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
                // &tls_ctx->security_parameters,
                // tls_ctx->key_block,
                key_block__t.data__pu8,
                key_block_len__alu16
              )
            );
          }
          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__set_ciphersuite(
              &tls_ctx->rec_prot__t,
              flea_tls_read,
              FLEA_TLS_CLIENT,
              tls_ctx->selected_cipher_suite__u16,
              key_block__t.data__pu8// tls_ctx->key_block
            )
          );
          if(!session_mbn__pt || !session_mbn__pt->for_resumption__u8)
          {
            /* in case of session resumption, this, the read direction, is the first direction to
             * switch to the new ciphersuite. thus, the key block is still
             * needed later on when the new session is set for the write direction.
             */
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
      flea_al_u16_t key_block_len__alu16;

      if(!session_mbn__pt || !session_mbn__pt->for_resumption__u8)
      {
        // if we have to send a certificate, send it now
        if((handshake_state.send_client_cert == FLEA_TRUE) && tls_ctx->cert_chain_mbn__pt)
        {
          FLEA_CCALL(
            THR_flea_tls__send_certificate(
              tls_ctx,
              &p_hash_ctx,
              tls_ctx->cert_chain_mbn__pt,
              tls_ctx->cert_chain_len__u8
            )
          );
        }
        FLEA_CCALL(
          THR_flea_tls__send_client_key_exchange(
            &hs_ctx__t,
            &p_hash_ctx,
            &peer_public_key__t,
            &premaster_secret__t
          )
        );

        // send CertificateVerify message if we sent a certificate
        if(handshake_state.send_client_cert == FLEA_TRUE)
        {
          if(tls_ctx->private_key_for_client_mbn__pt)
          {
            FLEA_CCALL(THR_flea_tls__send_cert_verify(tls_ctx, &p_hash_ctx));
          }
          handshake_state.send_client_cert = FLEA_FALSE;
        }
      }
      // send change cipher spec (initiate encryption/authentication)
      FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx));

      /*
       * Enable encryption for outgoing messages
       */
      if(!session_mbn__pt || !session_mbn__pt->for_resumption__u8)
      {
        // TODO: MASTER SECRET NEED NOT BE IN TLS_CTX
        FLEA_CCALL(
          THR_flea_tls__create_master_secret(
            // tls_ctx->client_and_server_random__bu8,
            &hs_ctx__t,
            &premaster_secret__t,
            tls_ctx->master_secret__bu8,
            (flea_tls__cipher_suite_id_t) tls_ctx->selected_cipher_suite__u16
          )
        );
        if(session_mbn__pt && session_mbn__pt->session_id_len__u8)
        {
          // store the PM and ciphersuite and later (after the finished) the seq
          memcpy(
            session_mbn__pt->session__t.master_secret__au8,
            tls_ctx->master_secret__bu8,
            FLEA_TLS_MASTER_SECRET_SIZE
          );
          session_mbn__pt->session__t.cipher_suite_id__u16 = tls_ctx->selected_cipher_suite__u16;
        }
      }
      else
      {
        // TODO: NOT NEEDED ANYMORE HERE
        /* it is a resumption */
        tls_ctx->selected_cipher_suite__u16 = session_mbn__pt->session__t.cipher_suite_id__u16;
        memcpy(
          tls_ctx->master_secret__bu8,
          session_mbn__pt->session__t.master_secret__au8,
          FLEA_TLS_MASTER_SECRET_SIZE
        );
      }
      if(!session_mbn__pt || !session_mbn__pt->for_resumption__u8)
      {
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
            // &tls_ctx->security_parameters,
            // tls_ctx->key_block,
            key_block__t.data__pu8,
            key_block_len__alu16
          )
        );
      }

      FLEA_CCALL(
        THR_flea_tls_rec_prot_t__set_ciphersuite(
          &tls_ctx->rec_prot__t,
          flea_tls_write,
          FLEA_TLS_CLIENT,
          tls_ctx->selected_cipher_suite__u16,
          key_block__t.data__pu8
          // tls_ctx->key_block
        )
      );


      FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &p_hash_ctx));
      if(!session_mbn__pt || !session_mbn__pt->for_resumption__u8)
      {
        handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
        continue;
      }
      else
      {
        handshake_state.finished = FLEA_TRUE;
        break;
      }
    }
  }
  if(tls_ctx->client_session_mbn__pt && tls_ctx->client_session_mbn__pt->session_id_len__u8)
  {
    flea_tls_session_data_t__set_session_as_valid(&tls_ctx->client_session_mbn__pt->session__t);
  }
  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&premaster_secret__t);
    flea_byte_vec_t__dtor(&key_block__t);
    flea_byte_vec_t__dtor(&client_and_server_random__t);
    flea_tls_parallel_hash_ctx_t__dtor(&p_hash_ctx);
    flea_public_key_t__dtor(&peer_public_key__t); // TODO: CAN THIS BE REUSED FOR ECDHE KEY?
    flea_public_key_t__dtor(&ecdhe_pub_key__t);
  );
} /* THR_flea_tls__client_handshake */

flea_err_t THR_flea_tls_client_ctx_t__ctor(
  flea_tls_client_ctx_t*     tls_client_ctx__pt,
  // flea_tls_ctx_t*               tls_ctx__pt,
  const flea_cert_store_t*   trust_store__pt,
  const flea_ref_cu8_t*      server_name__pcrcu8,
  flea_host_id_type_e        host_name_id__e,
  flea_rw_stream_t*          rw_stream__pt,
  flea_ref_cu8_t*            cert_chain_mbn__pt,
  flea_al_u8_t               cert_chain_len__alu8,
  flea_private_key_t*        private_key_mbn__pt,
  const flea_ref_cu16_t*     allowed_cipher_suites__prcu16,
  // flea_rev_chk_mode_e           rev_chk_mode__e,
  const flea_byte_vec_t*     crl_der__pt,
  flea_al_u16_t              nb_crls__alu16,
  flea_tls_client_session_t* session_mbn__pt,
  // flea_tls_renegotiation_spec_e reneg_spec__e,
  flea_ref_cu8_t*            allowed_ecc_curves_ref__prcu8,
  flea_ref_cu8_t*            allowed_sig_algs_ref__prcu8,
  // flea_tls_flag_e               flags
  flea_al_u16_t              flags__alu16
)
{
  flea_err_t err__t;

  flea_tls_ctx_t* tls_ctx__pt = &tls_client_ctx__pt->tls_ctx__t;

  // flea_hostn_validation_params_t hostn_valid_params__t;
  FLEA_THR_BEG_FUNC();
  tls_ctx__pt->cfg_flags__u16 = flags__alu16;
  // tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e = rev_chk_mode__e;
  tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16 = nb_crls__alu16;
  tls_ctx__pt->rev_chk_cfg__t.crl_der__pt  = crl_der__pt;
  tls_ctx__pt->cert_chain_mbn__pt = cert_chain_mbn__pt;
  tls_ctx__pt->cert_chain_len__u8 = cert_chain_len__alu8;
  tls_ctx__pt->allowed_cipher_suites__prcu16 = allowed_cipher_suites__prcu16;
  tls_ctx__pt->client_session_mbn__pt        = session_mbn__pt;
  tls_ctx__pt->allowed_ecc_curves__rcu8      = *allowed_ecc_curves_ref__prcu8;
  tls_ctx__pt->allowed_sig_algs__rcu8        = *allowed_sig_algs_ref__prcu8;
  tls_ctx__pt->extension_ctrl__u8 = 0;
  tls_ctx__pt->private_key_for_client_mbn__pt = private_key_mbn__pt;
  if(((cert_chain_mbn__pt != NULL) && (private_key_mbn__pt == NULL)) ||
    ((cert_chain_mbn__pt == NULL) && (private_key_mbn__pt != NULL)))
  {
    FLEA_THROW("certificate chain and private key must both be provided or neither", FLEA_ERR_INV_ARG);
  }

  /*if(cert_chain__pt != NULL && client_private_key__pt != NULL)
   * {
   * FLEA_CCALL(
   *  THR_flea_private_key_t__ctor_pkcs8(
   *    &tls_ctx__pt->private_key__t,
   *    client_private_key__pt->data__pcu8,
   *    client_private_key__pt->len__dtl
   *  )
   * );
   * }*/

  if(server_name__pcrcu8)
  {
    tls_client_ctx__pt->hostn_valid_params__t.host_id__ct = *server_name__pcrcu8;
  }
  else
  {
    tls_client_ctx__pt->hostn_valid_params__t.host_id__ct.data__pcu8 = NULL;
    tls_client_ctx__pt->hostn_valid_params__t.host_id__ct.len__dtl   = 0;
  }
  // tls_ctx->hostn_valid_params__t.host_id__ct.len__dtl = strlen(server_name__cs);
  tls_client_ctx__pt->hostn_valid_params__t.host_id_type__e = host_name_id__e;

  tls_ctx__pt->trust_store__pt = trust_store__pt;

  tls_ctx__pt->connection_end = FLEA_TLS_CLIENT;

  FLEA_CCALL(
    THR_flea_tls_ctx_t__construction_helper(
      tls_ctx__pt,
      rw_stream__pt
      // reneg_spec__e
    )
  );
  // TODO: REMOVE SESSION-OBJ AGAIN FROM FUNCTION SIGNATURES, IT IS NOW IN THE
  // TLS_CTX
  err__t = THR_flea_tls__client_handshake(tls_ctx__pt, session_mbn__pt, &tls_client_ctx__pt->hostn_valid_params__t);
  FLEA_CCALL(THR_flea_tls__handle_tls_error(NULL, tls_client_ctx__pt, err__t, NULL, FLEA_FALSE));
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__ctor_client */

flea_err_t THR_flea_tls_ctx_t__client_handle_server_initiated_reneg(
  flea_tls_ctx_t*                       tls_ctx__pt,
  const flea_hostn_validation_params_t* hostn_valid_params__pt
)
{
  FLEA_DECL_OBJ(handsh_rdr__t, flea_tls_handsh_reader_t);
  flea_al_u8_t handsh_type__u8;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_handsh_reader_t__ctor(&handsh_rdr__t, &tls_ctx__pt->rec_prot__t));
  handsh_type__u8 = flea_tls_handsh_reader_t__get_handsh_msg_type(&handsh_rdr__t);
  if(handsh_type__u8 != HANDSHAKE_TYPE_HELLO_REQUEST)
  {
    FLEA_THROW("unexpected handshake message", FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH);
  }
  // # ifdef FLEA_TLS_HAVE_RENEGOTIATION
  FLEA_CCALL(THR_flea_tls__client_handshake(tls_ctx__pt, tls_ctx__pt->client_session_mbn__pt, hostn_valid_params__pt));

  /*# else
   * flea_tls_rec_prot_t__discard_current_read_record(&tls_ctx__pt->rec_prot__t);
   * FLEA_CCALL(
   *  THR_flea_tls_rec_prot_t__send_alert(
   *    &tls_ctx__pt->rec_prot__t,
   *    FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION,
   *    FLEA_TLS_ALERT_LEVEL_WARNING
   *  )
   * );
   # endif*/
  FLEA_THR_FIN_SEC(
    flea_tls_handsh_reader_t__dtor(&handsh_rdr__t);
  );
}

flea_err_t THR_flea_tls_client_ctx_t__read_app_data(
  flea_tls_client_ctx_t*  tls_client_ctx__pt,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
)
{
  return THR_flea_tls_ctx_t__read_app_data(
    NULL,
    tls_client_ctx__pt,
    data__pu8,
    data_len__palu16,
    rd_mode__e,
    &tls_client_ctx__pt->hostn_valid_params__t
  );
}

flea_err_t THR_flea_tls_client_ctx_t__send_app_data(
  flea_tls_client_ctx_t* tls_client_ctx__pt,
  const flea_u8_t*       data__pcu8,
  flea_dtl_t             data_len__dtl
)
{
  return THR_flea_tls_ctx_t__send_app_data(NULL, tls_client_ctx__pt, data__pcu8, data_len__dtl);
}

flea_err_t THR_flea_tls_client_ctx_t__flush_write_app_data(flea_tls_client_ctx_t* tls_client_ctx__pt)
{
  return THR_flea_tls_ctx_t__flush_write_app_data(&tls_client_ctx__pt->tls_ctx__t);
}

flea_err_t THR_flea_tls_client_ctx_t__renegotiate(
  flea_tls_client_ctx_t*   tls_client_ctx__pt,
  flea_bool_t*             result__pb,
  const flea_cert_store_t* trust_store__pt,
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  // flea_rev_chk_mode_e      rev_chk_mode__e,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
)
{
  return THR_flea_tls_ctx_t__renegotiate(
    NULL,
    tls_client_ctx__pt,
    result__pb,
    trust_store__pt,
    cert_chain__pt,
    cert_chain_len__alu8,
    allowed_cipher_suites__prcu16,
    // rev_chk_mode__e,
    crl_der__pt,
    nb_crls__alu16,
    &tls_client_ctx__pt->hostn_valid_params__t
  );
}

# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
flea_bool_t flea_tls_client_ctx_t__have_peer_ee_cert_ref(flea_tls_client_ctx_t* client_ctx__pt)
{
  return client_ctx__pt->tls_ctx__t.peer_ee_cert_data__t.len__dtl != 0;
}

const flea_x509_cert_ref_t* flea_tls_client_ctx_t__get_peer_ee_cert_ref(flea_tls_client_ctx_t* client_ctx__pt)
{
  if(flea_tls_client_ctx_t__have_peer_ee_cert_ref(client_ctx__pt))
  {
    return &client_ctx__pt->tls_ctx__t.peer_ee_cert_ref__t;
  }
  return NULL;
}

# endif /* ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF */

# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
flea_bool_t flea_tls_client_ctx_t__have_peer_root_cert_ref(flea_tls_client_ctx_t* client_ctx__pt)
{
  return client_ctx__pt->tls_ctx__t.peer_root_cert_set__u8;
}

const flea_x509_cert_ref_t* flea_tls_client_ctx_t__get_peer_root_cert_ref(flea_tls_client_ctx_t* client_ctx__pt)
{
  if(flea_tls_client_ctx_t__have_peer_root_cert_ref(client_ctx__pt))
  {
    return &client_ctx__pt->tls_ctx__t.peer_root_cert_ref__t;
  }
  return NULL;
}

# endif /* ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF */
void flea_tls_client_ctx_t__dtor(flea_tls_client_ctx_t* tls_client_ctx__pt)
{
  flea_tls_ctx_t__dtor(&tls_client_ctx__pt->tls_ctx__t);
}

#endif /* ifdef FLEA_HAVE_TLS */
