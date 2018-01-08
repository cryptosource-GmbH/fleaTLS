/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_common__H_
#define _flea_tls_common__H_

#include "internal/common/default.h"
#include "internal/common/tls_ciph_suite.h"
#include "internal/common/tls/tls_cert_path.h"
#include "internal/common/tls/parallel_hash.h"
#include "flea/tls_client_session.h"
#include "flea/tls.h"
#include "flea/tls_fwd.h"

#ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
extern "C" {
# endif


# define NO_COMPRESSION                           0

# define FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES 0x01
# define FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS    0x02
# define FLEA_TLS_EXT_CTRL_MASK__UNMATCHING       0x04

# define FLEA_TLS_EXT_TYPE__RENEG_INFO            0xff01
# define FLEA_TLS_EXT_TYPE__SUPPORTED_CURVES      0x000a
# define FLEA_TLS_EXT_TYPE__POINT_FORMATS         0x000b
# define FLEA_TLS_EXT_TYPE__SIGNATURE_ALGORITHMS  0x000d


flea_err_e THR_flea_tls__read_certificate(
  flea_tls_ctx_t*                    tls_ctx,
  flea_tls_handsh_reader_t*          hs_rdr__pt,
  flea_public_key_t*                 pubkey,
  flea_tls_cert_path_params_t const* cert_path_params__pct
);

flea_err_e THR_flea_tls__send_certificate(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  const flea_ref_cu8_t*         cert_chain__pt,
  flea_u8_t                     cert_chain_len__u8
);

flea_err_e THR_flea_tls__send_handshake_message_hdr(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  HandshakeType                 type,
  flea_u32_t                    content_len__u32
);

flea_err_e THR_flea_tls__send_handshake_message_content(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  const flea_u8_t*              msg_bytes,
  flea_u32_t                    msg_bytes_len
);

flea_err_e THR_flea_tls__send_handshake_message(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  HandshakeType                 type,
  const flea_u8_t*              msg_bytes,
  flea_u32_t                    msg_bytes_len
);

flea_err_e THR_flea_tls__read_finished(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_hash_ctx_t*          hash_ctx
);

typedef struct
{
  flea_u16_t  expected_messages;
  flea_bool_e finished;
  flea_bool_e initialized;
  flea_bool_e send_client_cert;
  flea_bool_e sent_first_round; // only relevant for server
} flea_tls__handshake_state_t;

typedef enum
{
  FLEA_TLS_HANDSHAKE_EXPECT_NONE                = 0x0, // zero <=> client needs to send his "second round"
  FLEA_TLS_HANDSHAKE_EXPECT_HELLO_REQUEST       = 0x1,
  FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO        = 0x2,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO        = 0x4,
  FLEA_TLS_HANDSHAKE_EXPECT_NEW_SESSION_TICKET  = 0x8,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE         = 0x10,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE = 0x20,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST = 0x40,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE   = 0x80,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_VERIFY  = 0x100,
  FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE = 0x200,
  FLEA_TLS_HANDSHAKE_EXPECT_FINISHED            = 0x400,
  FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC  = 0x800
} flea_tls__expect_handshake_type_t;
# define FLEA_TLS_SEC_RENEG_FINISHED_SIZE 12
# define FLEA_TLS_VERIFY_DATA_SIZE        12
flea_err_e THR_flea_tls__send_change_cipher_spec(
  flea_tls_ctx_t* tls_ctx
);

flea_err_e THR_flea_tls__send_finished(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx
);

flea_err_e THR_flea_tls_ctx_t__construction_helper(
  flea_tls_ctx_t*   ctx,
  flea_rw_stream_t* rw_stream__pt
);

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state);

flea_err_e THR_flea_tls__create_master_secret(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_byte_vec_t*          premaster_secret__pt
);


flea_err_e THR_flea_tls__generate_key_block(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_al_u16_t             selected_cipher_suite__alu16,
  flea_u8_t*                key_block,
  flea_al_u8_t              key_block_len__alu8
);

/**
 * Takes care of alert sending based on the type of error that occured. Throws
 * an error if the TLS session is terminated due to the error.
 */
flea_err_e THR_flea_tls__handle_tls_error(
  flea_tls_server_ctx_t* server_ctx_mbn__pt,
  flea_tls_client_ctx_t* client_ctx_mbn__pt,
  flea_err_e             err__t,
  flea_bool_e*           is_reneg_in__was_accepted_out_mbn___pb,
  flea_bool_e            is_read_app_data__b
);

flea_err_e THR_flea_tls_ctx_t__read_app_data(
  flea_tls_server_ctx_t*          server_ctx_mbn__pt,
  flea_tls_client_ctx_t*          client_ctx_mbn__pt,
  flea_u8_t*                      data__pu8,
  flea_dtl_t*                     data_len__pdtl,
  flea_stream_read_mode_e         rd_mode__e,
  flea_hostn_validation_params_t* hostn_valid_params_mbn__pt
);

flea_err_e THR_flea_tls_ctx_t__send_app_data(
  flea_tls_server_ctx_t* server_ctx_mbn,
  flea_tls_client_ctx_t* client_ctx_mbn,
  const flea_u8_t*       data,
  flea_dtl_t             data_len
);

flea_err_e THR_flea_tls_ctx_t__flush_write_app_data(flea_tls_ctx_t* tls_ctx);

flea_err_e THR_flea_tls__server_handshake(
  flea_tls_server_ctx_t* server_ctx__pt,
  flea_bool_e            is_reneg__b
);

flea_err_e THR_flea_tls__client_handshake(
  flea_tls_ctx_t*                       tls_ctx,
  flea_tls_client_session_t*            session_mbn__pt,
  const flea_hostn_validation_params_t* hostn_valid_params__pt,
  flea_bool_e                           is_reneg__b
);

/**
 * send a positive iteger big endian encoded as part of a handshake message.
 */
flea_err_e THR_flea_tls__send_handshake_message_int_be(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  flea_u32_t                    int__u32,
  flea_al_u8_t                  int_byte_width__alu8
);

flea_bool_e flea_tls__is_cipher_suite_ecdhe_suite(flea_tls_cipher_suite_id_t suite_id);

flea_err_e THR_flea_tls_ctx_t__parse_hello_extensions(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_bool_e*              found_sec_reneg__pb,
  flea_private_key_t*       priv_key_mbn__pt
);

flea_al_u16_t flea_tls_ctx_t__compute_extensions_length(flea_tls_ctx_t* tls_ctx__pt);

flea_err_e THR_flea_tls_ctx_t__send_extensions_length(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt
);

flea_err_e THR_flea_tls_ctx_t__send_reneg_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);

flea_bool_e flea_tls_ctx_t__do_send_sec_reneg_ext(flea_tls_ctx_t* tls_ctx__pt);


flea_err_e THR_flea_tls_ctx_t__send_ecc_point_format_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);

flea_err_e THR_flea_tls_ctx_t__send_ecc_supported_curves_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);

void flea_tls_set_tls_random(flea_tls_handshake_ctx_t* ctx__pt);

flea_mac_id_e flea_tls__map_hmac_to_hash(flea_hash_id_e h);

/*flea_err_e THR_flea_tls_ctx_t__client_handle_server_initiated_reneg(
 * flea_tls_ctx_t* tls_ctx__pt
 * );*/

flea_err_e THR_flea_tls_ctx_t__send_extensions(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);

flea_err_e THR_flea_tls__check_sig_alg_compatibility_for_key_type(
  flea_pk_key_type_e  key_type__t,
  flea_pk_scheme_id_e pk_scheme_id__t
);

flea_err_e THR_flea_tls__map_flea_hash_to_tls_hash(
  flea_hash_id_e hash_id__t,
  flea_u8_t*     id__pu8
);

flea_err_e THR_flea_tls__map_tls_hash_to_flea_hash(
  flea_u8_t       id__u8,
  flea_hash_id_e* hash_id__pt
);

flea_err_e THR_flea_tls__map_flea_sig_to_tls_sig(
  flea_pk_scheme_id_e pk_scheme_id__t,
  flea_u8_t*          id__pu8
);

flea_err_e THR_flea_tls__map_tls_sig_to_flea_sig(
  flea_u8_t            id__u8,
  flea_pk_scheme_id_e* pk_scheme_id__pt
);

flea_err_e THR_flea_tls__read_sig_algs_field_and_find_best_match(
  flea_tls_ctx_t*     tls_ctx__pt,
  flea_rw_stream_t*   hs_rd_stream__pt,
  flea_u16_t          sig_algs_len__u16,
  flea_private_key_t* priv_key_mbn__pt
);

flea_err_e THR_flea_tls_ctx_t__parse_sig_alg_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
);

flea_err_e THR_flea_tls_ctx_t__send_sig_alg_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);

flea_pk_scheme_id_e flea_tls__get_sig_alg_from_key_type(
  flea_pk_key_type_e key_type__t
);

flea_u8_t flea_tls__get_tls_cert_type_from_flea_key_type(flea_pk_key_type_e key_type__t);

flea_u8_t flea_tls__get_tls_cert_type_from_flea_pk_scheme(flea_pk_scheme_id_e pk_scheme__t);

void flea_tls_ctx_t__dtor(flea_tls_ctx_t* tls_ctx__pt);

flea_err_e THR_flea_tls_ctx_t__renegotiate(
  flea_tls_server_ctx_t*            server_ctx_mbn__pt,
  flea_tls_client_ctx_t*            client_ctx_mbn__pt,
  flea_bool_e*                      result__pb,
  flea_private_key_t*               private_key__pt,
  const flea_cert_store_t*          trust_store__pt,
  const flea_ref_cu8_t*             cert_chain__pt,
  flea_al_u8_t                      cert_chain_len__alu8,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites__pe,
  flea_al_u16_t                     nb_allowed_cipher_suites__alu16,
  const flea_ref_cu8_t*             crl_der__pt,
  flea_al_u16_t                     nb_crls__alu16,
  flea_ec_dom_par_id_e*             allowed_ecc_curves__pe,
  flea_al_u16_t                     nb_allowed_curves__alu16,
  flea_tls_sigalg_e*                allowed_sig_algs__pe,
  flea_al_u16_t                     nb_allowed_sig_algs__alu16,
  flea_hostn_validation_params_t*   hostn_valid_params_mbn__pt
);

flea_bool_e flea_is_in_ciph_suite_list(
  flea_tls_cipher_suite_id_t        sought_for__e,
  const flea_tls_cipher_suite_id_t* list__pe,
  flea_al_u16_t                     list_len__alu16
);

void flea_tls_ctx_t__begin_handshake(flea_tls_ctx_t* tls_ctx__pt);

# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_TLS
#endif /* h-guard */
