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

#ifndef _flea_tls_common_ecc__H_
#define _flea_tls_common_ecc__H_

#include "internal/common/default.h"
#include "internal/common/tls/tls_int.h"
#ifdef __cplusplus
extern "C" {
#endif


#ifdef FLEA_HAVE_TLS_CS_ECC

flea_err_e THR_flea_tls_ctx_t__parse_supported_curves_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
);


flea_err_e THR_flea_tls_ctx_t__parse_point_formats_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
);

flea_bool_t flea_tls__is_cipher_suite_ecdhe_suite(flea_tls_cipher_suite_id_t suite_id);

flea_bool_t flea_tls__is_cipher_suite_ecc_suite(flea_tls_cipher_suite_id_t suite_id);

flea_err_e THR_flea_tls__map_curve_bytes_to_flea_curve(
  const flea_u8_t       bytes[2],
  flea_ec_dom_par_id_e* ec_dom_par_id__pt
);
flea_err_e THR_flea_tls__map_flea_curve_to_curve_bytes(
  const flea_ec_dom_par_id_e ec_dom_par_id__pt,
  flea_u8_t                  bytes[2]
);

flea_err_e THR_flea_tls_ctx_t__send_supported_ec_curves_ext(
  flea_tls_ctx_t*          tls_ctx__pt,
  flea_tls_prl_hash_ctx_t* p_hash_ctx__pt
);

flea_bool_t flea_tls__is_cipher_suite_ecc_suite(flea_tls_cipher_suite_id_t suite_id);

flea_err_e THR_flea_tls_ctx_t__parse_supported_curves_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
);

flea_err_e THR_flea_tls_ctx_t__parse_point_formats_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
);

# ifdef FLEA_HAVE_TLS_CS_ECDHE
flea_err_e THR_flea_tls__create_ecdhe_key(
  flea_privkey_t*      priv_key__pt,
  flea_pubkey_t*       pub_key__pt,
  flea_ec_dom_par_id_e dom_par_id__t
);

flea_err_e THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* hs_rd_stream__pt,
  flea_byte_vec_t*  premaster_secret__pt,
  flea_privkey_t*   priv_key__pt,
  flea_pubkey_t*    peer_pubkey__pt
);
# endif // ifdef FLEA_HAVE_TLS_CS_ECDHE

#endif // ifdef FLEA_HAVE_TLS_CS_ECC

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
