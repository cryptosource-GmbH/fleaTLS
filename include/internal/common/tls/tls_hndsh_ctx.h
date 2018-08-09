/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_tls_hndsh_ctx__H_
# define _flea_tls_hndsh_ctx__H_

# include "internal/common/algo_len_int.h"
# include "internal/common/default.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "flea/byte_vec.h"
# include "flea/pubkey.h"
# include "internal/common/tls/dtls_stream.h"
# include "internal/common/tls/tls_hndsh_ctx_fwd.h"
# include "qheap/queue_heap.h"


# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_u32_t fragm_offs__u32;
  flea_u32_t fragm_len__u32;
  flea_u32_t msg_len__u32;
  flea_u16_t msg_seq__u16;
  flea_u8_t  msg_type__u8;
} flea_dtls_hndsh_hdr_info_t;

# define FLEA_DTLS_HNDSH_HDR_FRGM_END(hdr_info__pt) ((hdr_info__pt)->fragm_offs__u32 + (hdr_info__pt)->fragm_len__u32)

typedef struct
{
  flea_u32_t                 fragm_len_incl_hs_hdr__u32;
  flea_u32_t                 rd_offs_incl_hdr__u32;
  flea_dtls_hndsh_hdr_info_t msg_hdr_info__t;
  qh_hndl_t                  hndl_qhh;
} flea_dtls_hndsh_msg_state_info_t;

typedef struct
{
# ifdef FLEA_STACK_MODE
  qh_hndl_t                        qheap_handles_incoming_memory__au8[FLEA_STKMD_DTLS_DTLS_MAX_NB_INCM_FRGMS];
# endif
  flea_dtls_rd_stream_hlp_t        dtls_rd_strm_hlp__t;
  flea_byte_vec_t                  qheap_handles_incoming__t;
# if 0
  flea_u16_t                       curr_msg_seq__u16; /* from hndsh-hdr, and next expected msg */
  flea_u32_t                       curr_msg_len__u32; /* from hndsh-hdr */
  flea_u32_t                       curr_fragm_len__u32; /* from hndsh-hdr, updated when receiving next adjacent fragment */
  flea_u32_t                       curr_fragm_offs__u32;
# endif // if 0
  flea_dtls_hndsh_msg_state_info_t curr_msg_state_info__t;
  flea_tls_rec_cont_type_e         req_next_rec_cont_type__e;

  // TODO: RELOCATE THIS STREAM SO THAT IT CAN BE THE SAME AS THE STREAM NEEDED TO BE INSTANTIATED BY THR_flea_tls_hndsh_rdr__ctor_tls->THR_flea_rw_stream_t__ctor_rec_prot
  flea_rw_stream_t                 dtls_assmbld_rd_stream__t;
// flea_dtls_hndsh_hdr_info_t curr_msg_hdr_info__t;
// flea_u8_t curr_hndsh_msg_type__u8; => this is stored in the handsh_rdr
} flea_dtls_hs_assmb_state_t;

struct struct_flea_dtls_hdsh_ctx_t
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
  flea_u8_t*                 hello_cookie__pu8;
  flea_u8_t                  hello_verify_tries__u8;
# endif
  qheap_queue_heap_t*        qheap__pt;
  // TODO: EITHER GLOBALLY PROVIDED OR FLEA/TLS-WIDE
  qheap_queue_heap_t         qheap__t;
  // TODO: PONDER VARIANTS OF HOW TO PLACE THIS BUFFER (STACK/HEAP?)
  flea_u32_t                 qh_mem_area__au32[(FLEA_QHEAP_MEMORY_SIZE + 3) / 4];
  flea_dtls_hs_assmb_state_t incom_assmbl_state__t;
};

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

// flea_err_e THR_flea_tls_handshake_ctx_t__ctor(flea_tls_handshake_ctx_t* hs_ctx__pt);
flea_err_e THR_flea_tls_handshake_ctx_t__ctor(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  // flea_recprot_t*           rec_prot__pt
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_bool_t               is_reneg__b
);

void flea_tls_handshake_ctx_t__dtor(flea_tls_handshake_ctx_t* hs_ctx__pt);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
