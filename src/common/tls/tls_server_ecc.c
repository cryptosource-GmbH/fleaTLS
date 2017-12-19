/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "internal/common/tls/tls_session_mngr_int.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "internal/common/tls/tls_server_int_ecc.h"
#include "internal/common/tls/tls_common_ecc.h"
#include "internal/common/tls_ciph_suite.h"

#ifdef FLEA_HAVE_TLS_ECC
flea_err_t THR_flea_tls_get_sig_length_of_priv_key(
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

#endif /* ifdef FLEA_HAVE_TLS_ECC */
#ifdef FLEA_HAVE_TLS_ECDHE
flea_err_t THR_flea_tls__send_server_kex(
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
    (flea_tls__cipher_suite_id_t) tls_ctx__pt->selected_cipher_suite__e
    );

  if(kex_method__t == FLEA_TLS_KEX_ECDHE)
  {
    // create ECDHE key pair
    FLEA_CCALL(
      THR_flea_tls__create_ecdhe_key(
        ecdhe_priv_key__pt,
        &ecdhe_pub_key__t,
        (flea_ec_dom_par_id_t) tls_ctx__pt->chosen_ecc_dp_internal_id__u8
      )
    );

    pub_point__rcu8 = flea_public_key__get_encoded_public_component(&ecdhe_pub_key__t);

    hdr_len__u32 = 3 + 1 + pub_point__rcu8.len__dtl + 2 + 2 + sig_len__u16; // 3 for named curve + 1 for pub point length + 2 for sig/hash alg + 2 sig length + len of sha256 sig

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
    FLEA_THROW("Invalid state", FLEA_ERR_INT_ERR);
  }

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&params_hash_ctx__t);
    FLEA_FREE_BUF_FINAL(hash__bu8);
    flea_byte_vec_t__dtor(&sig_vec__t);
    flea_public_key_t__dtor(&ecdhe_pub_key__t);
  );
} /* THR_flea_tls__send_server_kex */

#endif   /* ifdef FLEA_HAVE_TLS_ECDHE */
