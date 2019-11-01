/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "internal/common/tls/tls_session_mngr_int.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "internal/common/tls/tls_server_int_ecc.h"
#include "internal/common/tls/tls_common_ecc.h"
#include "internal/common/tls/tls_ciph_suite.h"
#include "flea/pk_keypair.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
#include "internal/common/tls/tls_hndsh_layer.h"


#ifdef FLEA_HAVE_TLS_CS_ECDHE
flea_err_e THR_flea_tls__send_server_kex_ecc(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt,
  flea_privkey_t*           ecdhe_priv_key__pt
)
{
  flea_tls__kex_method_t kex_method__t;

  flea_hash_ctx_t params_hash_ctx__t;

  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  flea_hash_ctx_t__INIT(&params_hash_ctx__t);
  FLEA_DECL_BUF(hash__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(sig_vec__t, FLEA_ASYM_MAX_ENCODED_SIG_LEN);
  flea_u8_t hash_out_len__u8;
  flea_u32_t hdr_len__u32;
  flea_ref_cu8_t pub_point__rcu8;
  flea_u8_t ec_curve_type__au8[] = {3}; // named_curve has value 3
  flea_hash_id_e hash_id__t;
  flea_pk_scheme_id_e pk_scheme_id__t;
  flea_u8_t sig_and_hash_alg[2];
  flea_u16_t sig_len__u16;
  flea_u8_t ec_curve__au8[2];
  flea_u8_t sig_len_enc__au8[2];
  flea_pubkey_t ecdhe_pub_key__t;
  flea_u8_t pub_point_len__u8;

  FLEA_THR_BEG_FUNC();
  flea_pubkey_t__INIT(&ecdhe_pub_key__t);
  FLEA_CCALL(THR_flea_tls__map_flea_curve_to_curve_bytes(tls_ctx__pt->chosen_ecc_dp_internal_id__u8, ec_curve__au8));

  hash_id__t      = tls_ctx__pt->chosen_hash_algorithm__t;
  pk_scheme_id__t = flea_tls__get_sig_alg_from_key_type(tls_ctx__pt->private_key__pt->key_type__t);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&params_hash_ctx__t, hash_id__t));
  hash_out_len__u8    = flea_hash_ctx_t__get_output_length(&params_hash_ctx__t);
  sig_and_hash_alg[0] = (flea_u8_t) hash_id__t;
  FLEA_CCALL(THR_flea_tls__map_flea_sig_to_tls_sig(pk_scheme_id__t, &sig_and_hash_alg[1]));

  kex_method__t = flea_tls_get_kex_method_by_cipher_suite_id(
    (flea_tls_cipher_suite_id_t) tls_ctx__pt->selected_cipher_suite__e
  );

  if(kex_method__t == FLEA_TLS_KEX_ECDHE)
  {
    /*
     * create ECDHE key pair
     */

    FLEA_CCALL(
      THR_flea_pubkey__by_dp_id_gen_ecc_key_pair(
        &ecdhe_pub_key__t,
        ecdhe_priv_key__pt,
        (flea_ec_dom_par_id_e) tls_ctx__pt->chosen_ecc_dp_internal_id__u8
      )
    );

    flea_pubkey_t__get_encoded_plain_ref(&ecdhe_pub_key__t, &pub_point__rcu8);
    pub_point_len__u8 = (flea_u8_t) pub_point__rcu8.len__dtl;

    /*
     * create signature of ECParams
     */

    // calculate hash of ECParams
    FLEA_CCALL(
      THR_flea_hash_ctx_t__update(
        &params_hash_ctx__t,
        hs_ctx__pt->client_and_server_random__pt->data__pu8,
        2 * FLEA_TLS_HELLO_RANDOM_SIZE
      )
    );
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, ec_curve_type__au8, sizeof(ec_curve_type__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, ec_curve__au8, sizeof(ec_curve__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, &pub_point_len__u8, 1));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&params_hash_ctx__t, pub_point__rcu8.data__pcu8, pub_point__rcu8.len__dtl));

    FLEA_ALLOC_BUF(hash__bu8, hash_out_len__u8);
    FLEA_CCALL(THR_flea_hash_ctx_t__final(&params_hash_ctx__t, hash__bu8));

    // sign it
    FLEA_CCALL(
      THR_flea_privkey_t__sign_digest(
        tls_ctx__pt->private_key__pt,
        pk_scheme_id__t,
        hash_id__t,
        hash__bu8,
        hash_out_len__u8,
        &sig_vec__t
      )
    );

    sig_len__u16 = sig_vec__t.len__dtl;
    flea__encode_U16_BE(sig_len__u16, sig_len_enc__au8);

    /*
     * send all of the data
     */

    hdr_len__u32 = 3 + 1 + pub_point__rcu8.len__dtl + 2 + 2 + sig_len__u16;   // 3 for named curve + 1 for pub point length + 2 for sig/hash alg + 2 sig length + len of signature

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_hdr(
        hs_ctx__pt,
        p_hash_ctx__pt,
        HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
        hdr_len__u32
      )
    );

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
        p_hash_ctx__pt,
        ec_curve_type__au8,
        1
      )
    );

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
        p_hash_ctx__pt,
        ec_curve__au8,
        2
      )
    );

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
        p_hash_ctx__pt,
        &pub_point_len__u8,
        1
      )
    );

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
        p_hash_ctx__pt,
        pub_point__rcu8.data__pcu8,
        pub_point__rcu8.len__dtl
      )
    );

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
        p_hash_ctx__pt,
        sig_and_hash_alg,
        2
      )
    );


    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
        p_hash_ctx__pt,
        sig_len_enc__au8,
        sizeof(sig_len_enc__au8)
      )
    );

    FLEA_CCALL(
      THR_flea_tls__snd_hands_msg_content(
        hs_ctx__pt,
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
    flea_pubkey_t__dtor(&ecdhe_pub_key__t);
  );
} /* THR_flea_tls__send_server_kex_ecc */

#endif   /* ifdef FLEA_HAVE_TLS_CS_ECDHE */
