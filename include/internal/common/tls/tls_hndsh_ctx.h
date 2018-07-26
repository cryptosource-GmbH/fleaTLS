/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_tls_hndsh_ctx__H_
# define _flea_tls_hndsh_ctx__H_

# include "internal/common/algo_len_int.h"
# include "internal/common/default.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "flea/byte_vec.h"
# include "flea/pubkey.h"


# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  // TODO:
  flea_u16_t alfj;
} flea_hs_msg_vn_assmb_buf_t;

typedef struct
{
  flea_s16_t send_msg_seq__s16;
/* first seq-no of the last completely received flight: */
  flea_s16_t rec_last_flight_initial_msg_seq__s16;
  flea_s16_t rec_last_flight_final_msg_seq__s16;

  /* seq-no of the hs-msg, from which at least the first header has been
   * received: */
  flea_s16_t    rec_msg_seq__s16;
  flea_u32_t    flight_buf_write_pos__u32;
  flea_u32_t    flight_buf_read_pos__u32;
  flea_u16_t    assembly_read_pos__u16;
  // flea_u16_t    assembly_write_pos__u16;
  flea_u8_t*    assembly_buf__pu8;
  flea_u8_t*    fragm_info_ptr__pu8;
  flea_al_u16_t pmtu_estimate__alu16;
  // flea_u16_t curr_frag_len__alu16;
  flea_u8_t     is_flight_buf_incoming__u8;
# ifdef FLEA_HEAP_MODE
  flea_u8_t*    flight_buf__bu8;
  // flea_u8_t*     hello_verify_cookie__bu8;
# else
  flea_u8_t     flight_buf__bu8[FLEA_DTLS_FLIGHT_BUF_SIZE];
  // flea_u8_t     hello_verify_cookie__bu8[FLEA_DTLS_SRV_HELLO_COOKIE_SIZE]
# endif // ifdef FLEA_HEAP_MODE
# ifdef FLEA_HAVE_TLS_SERVER
  flea_u8_t* hello_cookie__pu8;
  flea_u8_t  hello_verify_tries__u8;
# endif
} flea_dtls_hdsh_ctx_t;

# define FLEA_DTLS_HDSH_CTX_HAVE_PEND_WRT_MSG(hs_ctx__pt)   ((hs_ctx__pt)->dtls_ctx__t.fragm_info_ptr__pu8 != 0)
# define FLEA_DTLS_HDSH_CTX_SET_NO_PEND_WRT_MSG(hs_ctx__pt) do {(hs_ctx__pt)->fragm_info_ptr__pu8 = 0;} while(0)

# if 0

typedef flea_err_e (* flea_send_handsh_msg_hdr_f)(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
);
# endif // if 0

// TOOD: ALL HANDSHAKE STRINGS TO HNDSH
struct struct_flea_tls_handshake_ctx_t
{
  flea_tls_ctx_t*      tls_ctx__pt;
  /* only used by tls_client: */
  flea_pubkey_t*       ecdhe_pub_key__pt;
  flea_byte_vec_t*     client_and_server_random__pt;
// flea_send_handsh_msg_hdr_f send_handsh_hdr__f;
  flea_u8_t            silent_alarm__u8;
  flea_u8_t            is_reneg__b;
  flea_bool_t          is_sess_res__b;
# ifdef FLEA_HAVE_DTLS
  flea_dtls_hdsh_ctx_t dtls_ctx__t;
# endif
};

flea_err_e THR_flea_tls_handshake_ctx_t__ctor(flea_tls_handshake_ctx_t* hs_ctx__pt);

void flea_tls_handshake_ctx_t__dtor(flea_tls_handshake_ctx_t* hs_ctx__pt);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
