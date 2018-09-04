/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_dtls_retransm_state__H_
# define _flea_dtls_retransm_state__H_

# include "internal/common/default.h"
# include "flea/timer.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "flea/tls.h"
# include "qheap/queue_heap.h"
# include "internal/common/tls/tls_rec_prot_fwd.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * type to hold a connection state for later activation.
 */
struct struct_flea_dtls_conn_state_data_t
{
# ifdef FLEA_STACK_MODE
  flea_u8_t                  write_key_block_mem__au8[FLEA_TLS_MAX_KEY_BLOCK_SIZE];
# endif
  flea_tls_cipher_suite_id_t cipher_suite_id;
  flea_byte_vec_t            write_key_block__t;
  // flea_u16_t previous_rec_sqn__u16;
  flea_u16_t                 write_epoch__u16;
  flea_u32_t                 write_sqn__au32 [2];
};

typedef struct
{
  // DONE in HS_CTX_CTOR: WHEN A HANDSHAKE IS STARTET, THIS MUST BE SET TO ZERO:
  // flea_u8_t is_in_sending_state__u8;
  flea_timer_t                timer__t;
  flea_dtls_conn_state_data_t previous_conn_st__t;
  flea_dtls_conn_state_data_t current_conn_st__t;
  flea_u8_t                   flight_buf_contains_ccs__u8;
  qh_hndl_t                   current_flight_buf__qhh;
  flea_u32_t                  flight_buf_read_pos__u32;
  qheap_queue_heap_t*         qheap__pt;
  flea_al_u16_t               pmtu_estimate__alu16;

  // TODO: EITHER GLOBALLY PROVIDED OR FLEA/TLS-WIDE
  qheap_queue_heap_t          qheap__t;
  // TODO: PONDER VARIANTS OF HOW TO PLACE THIS BUFFER (STACK/HEAP?)
  flea_u32_t                  qh_mem_area__au32[(FLEA_QHEAP_MEMORY_SIZE + 3) / 4];
} flea_dtls_retransm_state_t;


flea_u32_t flea_dtls_rtrsm_st_t__flight_buf_avail_send_len(
  flea_dtls_retransm_state_t* rtrsm_st__pt
);

flea_err_e THR_flea_dtls_rtrsm_st_t__try_send_out_from_flight_buf(
  flea_dtls_retransm_state_t*  dtls_rtrsm_st__pt,
  flea_tls__connection_end_t   conn_end__e,
  flea_recprot_t*              rec_prot__pt,
  flea_dtls_conn_state_data_t* conn_state_to_activate_after_ccs_mbn__pt
) FLEA_ATTRIB_UNUSED_RESULT;


flea_err_e THR_flea_dtls_rtrsm_st_t__append_to_flight_buffer_and_try_to_send_record(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_tls__connection_end_t  conn_end__e,
  flea_recprot_t*             rec_prot__pt,
  flea_u8_t*                  is_in_sending_state__pu8,
  const flea_u8_t*            data__pcu8,
  flea_u32_t                  data_len__u32
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_dtls_rtrsm_st_t__append_ccs_to_flight_buffer_and_try_to_send_record(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_tls__connection_end_t  conn_end__e,
  flea_recprot_t*             rec_prot__pt,
  flea_u8_t*                  is_in_sending_state__pu8
) FLEA_ATTRIB_UNUSED_RESULT;

void flea_dtls_rtrsm_st_t__empty_flight_buf(flea_dtls_retransm_state_t* dtls_retransm_state__pt);


flea_err_e THR_flea_dtls_rtrsm_t__retransmit_flight_buf(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_recprot_t*             rec_prot__pt,
  flea_tls__connection_end_t  conn_end__e
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
