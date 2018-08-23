/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_rec_prot__H_
# define _flea_tls_rec_prot__H_

# include "flea/types.h"
# include "flea/error.h"
# include "internal/common/tls/tls_ciph_suite.h"
# include "internal/common/tls/tls_conn_state.h"
# include "internal/common/tls/tls_ctx_fwd.h"
// #include "internal/common/tls/tls_common.h"
# include "flea/rw_stream.h"
# include "internal/common/tls/tls_rec_prot_fwd.h"
# ifdef FLEA_HAVE_DTLS
#  include "qheap/queue_heap.h"
# endif

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_DTLS
#  define FLEA_XTLS_MAX_RECORD_HDR_LEN FLEA_DTLS_RECORD_HDR_LEN
# else
#  define FLEA_XTLS_MAX_RECORD_HDR_LEN FLEA_TLS_RECORD_HDR_LEN
# endif

# ifdef FLEA_HAVE_TLS


#  define FLEA_RP_CTRL__DTLS_BIT                      (1 << 0)
#  define FLEA_RP_CTRL__WRITE_ONGOING_BIT             (1 << 1)
#  define FLEA_RP_CTRL__SESSION_CLOSED_BIT            (1 << 2)
#  define FLEA_RP_CTRL__CURRENT_RECORD_ALERT_BIT      (1 << 3)
#  define FLEA_RP_CTRL__PENDING_CLOSE_NOTIFY_BIT      (1 << 4)
#  define FLEA_RP_CTRL__IN_HANDSHAKE_IN_NEW_EPOCH_BIT (1 << 5)
#  define FLEA_RP_CTRL__DTLS_REC_FROM_FUT_EPOCH_BIT   (1 << 6)

#  define FLEA_RP__SET_DTLS(rec_prot__pt)          ((rec_prot__pt)->ctrl_field__u8 |= FLEA_RP_CTRL__DTLS_BIT)
#  define FLEA_RP__IS_DTLS(rec_prot__pt)           ((rec_prot__pt)->ctrl_field__u8 & FLEA_RP_CTRL__DTLS_BIT)

#  define FLEA_RP__SET_WRITE_ONGOING(rec_prot__pt) ((rec_prot__pt)->ctrl_field__u8 |= FLEA_RP_CTRL__WRITE_ONGOING_BIT)
#  define FLEA_RP__SET_NO_WRITE_ONGOING(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 &= \
  (~FLEA_RP_CTRL__WRITE_ONGOING_BIT))
#  define FLEA_RP__IS_WRITE_ONGOING(rec_prot__pt)  ((rec_prot__pt)->ctrl_field__u8 & FLEA_RP_CTRL__WRITE_ONGOING_BIT)


#  define FLEA_RP__SET_SESSION_CLOSED(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 |= \
  FLEA_RP_CTRL__SESSION_CLOSED_BIT)
#  define FLEA_RP__IS_SESSION_CLOSED(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 \
  & FLEA_RP_CTRL__SESSION_CLOSED_BIT)

#  define FLEA_RP__SET_CURRENT_RECORD_ALERT(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 |= \
  FLEA_RP_CTRL__CURRENT_RECORD_ALERT_BIT)
#  define FLEA_RP__SET_NOT_CURRENT_RECORD_ALERT(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 &= \
  (~FLEA_RP_CTRL__CURRENT_RECORD_ALERT_BIT))
#  define FLEA_RP__IS_CURRENT_RECORD_ALERT(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 \
  & FLEA_RP_CTRL__CURRENT_RECORD_ALERT_BIT)

#  define FLEA_RP__SET_PENDING_CLOSE_NOTIFY(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 |= \
  FLEA_RP_CTRL__PENDING_CLOSE_NOTIFY_BIT)
#  define FLEA_RP__SET_NO_PENDING_CLOSE_NOTIFY(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 &= \
  (~FLEA_RP_CTRL__PENDING_CLOSE_NOTIFY_BIT))
#  define FLEA_RP__IS_PENDING_CLOSE_NOTIFY(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 \
  & FLEA_RP_CTRL__PENDING_CLOSE_NOTIFY_BIT)


/*# define FLEA_RP__SET_IN_HANDSHAKE_IN_NEW_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 |= \
  FLEA_RP_CTRL__IN_HANDSHAKE_IN_NEW_EPOCH_BIT)
# define FLEA_RP__IS_IN_HANDSHAKE_IN_NEW_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 \
  & FLEA_RP_CTRL__IN_HANDSHAKE_IN_NEW_EPOCH_BIT)*/


#  define FLEA_RP__SET_DTLS_REC_FROM_FUT_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 |= \
  FLEA_RP_CTRL__DTLS_REC_FROM_FUT_EPOCH_BIT)
#  define FLEA_RP__SET_NO_DTLS_REC_FROM_FUT_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 &= \
  (~FLEA_RP_CTRL__DTLS_REC_FROM_FUT_EPOCH_BIT))
#  define FLEA_RP__IS_DTLS_REC_FROM_FUT_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 \
  & FLEA_RP_CTRL__DTLS_REC_FROM_FUT_EPOCH_BIT)


#  define FLEA_TLS_RECORD_HDR_LEN      5
#  define FLEA_DTLS_RECORD_HDR_LEN     (FLEA_TLS_RECORD_HDR_LEN + 8)

#  define FLEA_TLS_TRNSF_BUF_SIZE      (FLEA_TLS_RECORD_MAX_RECEIVE_SIZE + FLEA_XTLS_MAX_RECORD_HDR_LEN)
#  define FLEA_TLS_ALT_SEND_BUF_SIZE   (FLEA_TLS_RECORD_MAX_SEND_SIZE + FLEA_XTLS_MAX_RECORD_HDR_LEN)
#  define FLEA_TLS_STD_MAX_RECORD_SIZE 18432

/**
 * Get the epoch of the currently held received record.
 */
#  define FLEA_RP__GET_RD_CURR_REC_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->read_state__t.seqno_lo_hi__au32[1] \
  >> 16)

typedef enum
{
  CONTENT_TYPE_ANY                = 0,
  CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20,
  CONTENT_TYPE_ALERT              = 21,
  CONTENT_TYPE_HANDSHAKE          = 22,
  CONTENT_TYPE_APPLICATION_DATA   = 23,
  CONTENT_TYPE_HEARTBEAT          = 24
} flea_tls_rec_cont_type_e;

typedef enum
{
  FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY                = 0,
  FLEA_TLS_ALERT_DESC_UNEXPECTED_MESSAGE          = 10,
  FLEA_TLS_ALERT_DESC_BAD_RECORD_MAC              = 20,
  FLEA_TLS_ALERT_DESC_RECORD_OVERFLOW             = 22,
  FLEA_TLS_ALERT_DESC_DECOMPRESSION_FAILURE       = 30,
  FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE           = 40,
  FLEA_TLS_ALERT_DESC_NO_CERTIFICATE_RESERVED     = 41,
  FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE             = 42,
  FLEA_TLS_ALERT_DESC_UNSUPPORTED_CERTIFICATE     = 43,
  FLEA_TLS_ALERT_DESC_CERTIFICATE_REVOKED         = 44,
  FLEA_TLS_ALERT_DESC_CERTIFICATE_EXPIRED         = 45,
  FLEA_TLS_ALERT_DESC_CERTIFICATE_UNKNOWN         = 46,
  FLEA_TLS_ALERT_DESC_ILLEGAL_PARAMETER           = 47,
  FLEA_TLS_ALERT_DESC_UNKNOWN_CA                  = 48,
  FLEA_TLS_ALERT_DESC_ACCESS_DENIED               = 49,
  FLEA_TLS_ALERT_DESC_DECODE_ERROR                = 50,
  FLEA_TLS_ALERT_DESC_DECRYPT_ERROR               = 51,
  FLEA_TLS_ALERT_DESC_EXPORT_RESTRICTION_RESERVED = 60,
  FLEA_TLS_ALERT_DESC_PROTOCOL_VERSION            = 70,
  FLEA_TLS_ALERT_DESC_INSUFFICIENT_SECURITY       = 71,
  FLEA_TLS_ALERT_DESC_INTERNAL_ERROR              = 80,
  FLEA_TLS_ALERT_DESC_USER_CANCELED               = 90,
  FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION            = 100,
  FLEA_TLS_ALERT_DESC_UNSUPPORTED_EXTENSION       = 110,
  FLEA_TLS_ALERT_DESC_UNKNOWN_PSK_IDENTITY        = 115,
  FLEA_TLS_ALERT_NO_ALERT                         = 255
} flea_tls__alert_description_t;

typedef enum
{
  FLEA_TLS_ALERT_LEVEL_WARNING = 1,
  FLEA_TLS_ALERT_LEVEL_FATAL   = 2
} flea_tls__alert_level_t;

// #define OLD_WR_EP
struct struct_flea_recprot_t
{
  flea_tls_con_stt_t read_state__t;
  flea_tls_con_stt_t write_state__t;
  // flea_u16_t         read_next_rec_epoch__u16;
// #ifdef OLD_WR_EP
// flea_u16_t         write_next_rec_epoch__u16;
// #endif
#  ifdef FLEA_HEAP_MODE
  flea_u8_t* send_rec_buf_raw__bu8;
  flea_u8_t* alt_send_buf__raw__bu8;
#  else
  flea_u8_t  send_rec_buf_raw__bu8[FLEA_TLS_TRNSF_BUF_SIZE + FLEA_TLS_RECORD_HDR_LEN ];
  flea_u8_t  alt_send_buf__raw__bu8[FLEA_TLS_ALT_SEND_BUF_SIZE];
#  endif // ifdef FLEA_HEAP_MODE
  flea_u16_t alt_send_buf__raw_len__u16;
  flea_u16_t send_rec_buf_raw_len__u16;
  flea_u8_t* payload_buf__pu8;
  flea_u8_t* send_payload_buf__pu8;
  flea_u8_t* send_buf_raw__pu8;
  // flea_u16_t                   payload_max_len__u16; // TODO: REMOVE THIS, NOT READ AT ALL
  // flea_u16_t                   alt_payload_max_len__u16;
  flea_u16_t record_plaintext_send_max_value__u16;                   // max. size for alt_payload_max_len__u16 (relevant for using the max fragment length extension)
  // flea_u16_t                   send_payload_max_len__u16;
  flea_u16_t curr_rec_content_len__u16;         // was payload_used_len__u16
  flea_u16_t curr_pt_content_len__u16;         // was payload_used_len__u16
  flea_u16_t send_curr_rec_content_len__u16;
  flea_u16_t curr_rec_content_offs__u16;
  flea_u16_t send_curr_rec_content_offs__u16;
  flea_u16_t reserved_payl_len__u16;

#  ifdef FLEA_HAVE_DTLS

  /**
   * if this variable is non-null, then in case of DTLS the record protocol is informed that after having sent out a CCS over the wire,
   * the
   */
  const flea_byte_vec_t*       key_block_indicate_ccs_retransm_mbn__pt;
#  endif
  flea_tls__protocol_version_t prot_version__t;
  // flea_u16_t tls_version__u16;
  flea_rw_stream_t*            rw_stream__pt;
  flea_u16_t                   raw_read_buf_content__u16;
  // flea_u16_t                   current_record_content_len__u16;
  flea_u8_t                    record_hdr_len__u8;
  flea_u8_t                    ctrl_field__u8;
  // flea_u8_t    is_curr_rec_from_future_epoch__u8;
//  flea_u8_t                    skip_empty_record__b;
};

#  define flea_recprot_t__INIT(__p) FLEA_ZERO_STRUCT(__p)


#  define flea_recprot_t__GET_CURR_REC_PT_SIZE(rec_prot__pt) (rec_prot__pt)->curr_pt_content_len__u16

#  define FLEA_RP__SET_NOT_IN_HANDSHAKE_IN_NEW_EPOCH(rec_prot__pt) \
  ((rec_prot__pt)->ctrl_field__u8 &= \
  (~FLEA_RP_CTRL__IN_HANDSHAKE_IN_NEW_EPOCH_BIT))

// TODO: THIS FUNCTION MUST BE CALLED BY CLIENT AND SERVER
#  ifdef FLEA_HAVE_DTLS
#   define FLEA_RECPROT_T__NOTIFY_HANDSHAKE_FINISHED(rec_prot__pt) \
  FLEA_RP__SET_NOT_IN_HANDSHAKE_IN_NEW_EPOCH( \
    rec_prot__pt \
  )
#  else // ifdef FLEA_HAVE_DTLS
#   define FLEA_RECPROT_T__NOTIFY_HANDSHAKE_FINISHED(rec_prot__pt)
#  endif // ifdef FLEA_HAVE_DTLS

#  define flea_recprot_t__SET_LO_WRT_STATE_SEQ_FROM_RD_STATE(rec_prot__pt) \
  do {(rec_prot__pt)->write_state__t. \
      seqno_lo_hi__au32[0] = \
        (rec_prot__pt)->read_state__t. \
        seqno_lo_hi__au32[0];} while(0)

void flea_recprot_t__dtor(flea_recprot_t* rec_prot__pt);

flea_err_e THR_flea_recprot_t__ctor(
  flea_recprot_t*   rec_prot__pt,
  flea_al_u8_t      prot_vers_major,
  flea_al_u8_t      prot_vers_minor,
  flea_rw_stream_t* rw_stream__pt,
  flea_bool_t       is_dtls__b
) FLEA_ATTRIB_UNUSED_RESULT;

void flea_recprot_t__set_null_ciphersuite(
  flea_recprot_t*       rec_prot__pt,
  flea_tls_stream_dir_e direction
);


flea_err_e THR_flea_recprot_t__wrt_data(
  flea_recprot_t*          rec_prot__pt,
  flea_tls_rec_cont_type_e content_type__e,
  const flea_u8_t*         data__pcu8,
  flea_dtl_t               data_len__dtl
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__write_flush(
  flea_recprot_t* rec_prot__pt
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__read_data(
  flea_recprot_t*          rec_prot__pt,
  flea_tls_rec_cont_type_e cont_type__e,
  flea_u8_t*               data__pu8,
  flea_dtl_t*              data_len__pdtl,
  flea_stream_read_mode_e  rd_mode__e
) FLEA_ATTRIB_UNUSED_RESULT;


flea_err_e THR_flea_recprot_t__get_current_record_type(
  flea_recprot_t*           rec_prot__pt,
  flea_tls_rec_cont_type_e* cont_type__pe,
  flea_stream_read_mode_e   rd_mode__e
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__send_record(
  flea_recprot_t*          rec_prot__pt,
  const flea_u8_t*         bytes,
  flea_dtl_t               bytes_len,
  flea_tls_rec_cont_type_e content_type
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__send_alert(
  flea_recprot_t*               rec_prot__pt,
  flea_tls__alert_description_t description,
  flea_tls__alert_level_t       level
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__send_alert_and_throw(
  flea_recprot_t*               rec_prot__pt,
  flea_tls__alert_description_t description,
  flea_err_e                    err__t
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__set_ciphersuite(
  flea_recprot_t*            rec_prot__pt,
  flea_tls_stream_dir_e      direction,
  flea_tls__connection_end_t conn_end__e,
  flea_tls_cipher_suite_id_t suite_id,
  const flea_u8_t*           key_block__pcu8
) FLEA_ATTRIB_UNUSED_RESULT;


flea_bool_t flea_recprot_t__have_done_initial_handshake(const flea_recprot_t* rec_prot__pt);

flea_al_u16_t flea_recprot_t__get_current_max_record_pt_size(flea_recprot_t* rec_prot__pt);

flea_al_u16_t flea_recprot_t__get_current_max_pt_expansion(flea_recprot_t* rec_prot__pt);

flea_al_u16_t flea_recprot_t__get_curr_wrt_rcrd_rem_free_len(const flea_recprot_t* rec_prot__pt);

void flea_recprot_t__discard_current_read_record(flea_recprot_t* rec_prot__pt);

flea_err_e THR_flea_recprot_t__close_and_send_close_notify(flea_recprot_t* rec_prot__pt) FLEA_ATTRIB_UNUSED_RESULT;

void flea_recprot_t__set_max_pt_len(
  flea_recprot_t* rec_prot__pt,
  flea_u16_t      pt_len__u16
);

#  ifdef FLEA_HAVE_DTLS
flea_err_e THR_flea_recprot_t__write_encr_rec_to_queue(
  flea_recprot_t*     rec_prot__pt,
  qheap_queue_heap_t* qh__pt,
  qh_al_hndl_t        hndl_for_encryped_rec__alqhh
) FLEA_ATTRIB_UNUSED_RESULT;


flea_err_e THR_flea_recprot_t__increment_read_epoch(flea_recprot_t* rec_prot__pt) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_recprot_t__set_encr_rd_rec_and_decrypt_it(
  flea_recprot_t*     rec_prot__pt,
  qheap_queue_heap_t* heap__pt,
  qh_al_hndl_t        hndl__alqhh
) FLEA_ATTRIB_UNUSED_RESULT;

flea_bool_t flea_recprot_t__is_rd_buf_empty(flea_recprot_t* rec_prot__pt);


#  endif // ifdef FLEA_HAVE_DTLS

#  ifdef FLEA_HEAP_MODE

flea_err_e THR_flea_recprot_t__resize_send_plaintext_size(
  flea_recprot_t* rec_prot__pt,
  flea_al_u16_t   new_len__alu16
) FLEA_ATTRIB_UNUSED_RESULT;
#  endif // ifdef FLEA_HEAP_MODE

# endif // ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
}
# endif
#endif /* h-guard */
