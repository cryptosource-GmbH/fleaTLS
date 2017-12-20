/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_common_ecc__H_
#define _flea_tls_common_ecc__H_

#include "internal/common/default.h"
#include "internal/common/tls/tls_int.h"
#ifdef __cplusplus
extern "C" {
#endif


#ifdef FLEA_HAVE_TLS_ECC

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
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
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

# ifdef FLEA_HAVE_TLS_ECDHE
flea_err_e THR_flea_tls__create_ecdhe_key(
  flea_private_key_t*  priv_key__pt,
  flea_public_key_t*   pub_key__pt,
  flea_ec_dom_par_id_e dom_par_id__t
);

flea_err_e THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret(
  flea_tls_ctx_t*     tls_ctx__pt,
  flea_rw_stream_t*   hs_rd_stream__pt,
  flea_byte_vec_t*    premaster_secret__pt,
  flea_private_key_t* priv_key__pt,
  flea_public_key_t*  peer_pubkey__pt
);
# endif // ifdef FLEA_HAVE_TLS_ECDHE

#endif // ifdef FLEA_HAVE_TLS_ECC

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
