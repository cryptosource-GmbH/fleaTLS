/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls/dtls_stream.h"

/*
 * recprot used in tls layer (tls_server, tls_client, tls_common):
 * for sending:
 * - THR_flea_recprot_t__send_record() for sending CCS (within THR_flea_tls__send_change_cipher_spec_directly())
 * - THR_flea_recprot_t__send_alert_and_throw() ==> can stay. alerts are small enought for
 *   single packet.
 * - THR_flea_recprot_t__send_alert() ==> "
 * - THR_flea_recprot_t__write_flush() ==> TODO: must be replaced, if it is really
 *   needed. Probably, introducing flight_sending_completed() calls will make
 *   explicit calls to write_flush() unnecessary.
 * - THR_flea_recprot_t__send_record() within THR_flea_tls_ctx_t__snd_appdat_inner() ==> TODO: must be replaced
 * - THR_flea_recprot_t__write_flush() within THR_flea_tls_ctx_t__flush_write_app_data() ==> TODO: must be replaced

 * - THR_flea_recprot_t__resize_send_plaintext_size() (resizing the send plaintext size) ==> TODO: must also be applied to the DTLS-package limit
 * - flea_recprot_t__set_max_pt_len()
 * - flea_recprot_t__have_done_initial_handshake() within flea_tls_ctx_t__compute_extensions_length() to check whether reneg content needs to be sent
 * - for setting new cipher suites ==> TODO: must be changed. When writing the
 *   records to the flight buffer, the cipher suite (connection state) is not yet applied. That
 *   means, once the the CCS was *written out* (not when it is appended to the flight buffer), the record protocol needs to switch to the new connection state. However, then it has to switch back to the previous to the previous connection state until the CCS is sent again. Alternative to write the "encrypted" records to the flight buffer is not possible: new records must be generated for resending.
 *
 * for reading:
 * - THR_flea_recprot_t__get_current_record_type()   ==> TODO: needs to be replaced
 * - THR_flea_recprot_t__read_data() for reading CCS ==> TODO: needs to be replaced
 * - for setting new cipher suites ==> TODO: when receiving records during a
 *   handshake, it can happen that a record sequentially after the CCS is
 *   received before the CCS. Thus the correct decryption of a record is only
 *   possible together with the knowledge whether it is sequentially before or
 *   after the CCS. However, it is known when the CCS is expected. Thus, the CCS
 *   will be read by the logic layer at the right time. But this means that
 *   records following the CCS cannot be decrypted until the CCS has been read
 *   by the logic layer. One possibility would be to buffer the undecrypted
 *   records, they can be ordered by the record sequence. Each record is
 *   decrypted only when it is being read from. But if there are gaps, then
 *   future records must be checked for containing a missing fragment.
 * - THR_flea_recprot_t__read_data() within THR_flea_tls_ctx_t__rd_appdat_inner() ==> TODO: needs to be replaced
 * - flea_recprot_t__discard_current_read_record() within THR_flea_tls_ctx_t__rd_appdat_inner() to reject renge request ==> TODO: needs to be replaced
 *
 *
 */

// stream to be used by handsh_rdr and by TLS logic layer directly
static flea_err_e THR_dtls_rd_strm_rd_func(
  void*                   custom_obj,
  flea_u8_t*              target_buffer,
  flea_dtl_t*             nb_bytes_to_read,
  flea_stream_read_mode_e read_mode
)
{
  FLEA_THR_BEG_FUNC();

  /* read the next record */

  /* TODO: remove the dtls handshake header fields */

  FLEA_THR_FIN_SEC_empty();
}

// dtls assembly layer for the handshake only
flea_err_e THR_flea_rw_stream_t__ctor_dtls_rd_strm(
  flea_rw_stream_t*          stream__pt,
  flea_dtls_rd_stream_hlp_t* hlp__pt,
  flea_dtls_hdsh_ctx_t*      dtls_ctx__pt,
  flea_recprot_t*            rec_prot__pt
)
{
  FLEA_THR_BEG_FUNC();

  hlp__pt->dtls_ctx__pt = dtls_ctx__pt;
  hlp__pt->rec_prot__pt = rec_prot__pt;
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      hlp__pt,
      NULL,
      NULL,
      THR_dtls_rd_strm_rd_func,
      NULL,
      NULL,
      0
    )
  );

  FLEA_THR_FIN_SEC_empty();
}
