/**
 * Append data to the byte vector from a read stream. If
 * the capacity of the internal buffer is
 * exceeded, in heap mode a reallocation is performed if necessary.
 *
 * @param byte_vec pointer to the byte_vector
 * @param read_stream__pt pointer to the stream to read from
 * @param len the length of data to be read and appended
 * @param rd_mode__e the mode in which the data shall be read from the stream
 */
flea_err_t THR_flea_rw_stream_t__read_to_byte_vec(
  flea_rw_stream_t*       read_stream__pt,
  flea_byte_vec_t*        byte_vec__pt,
  flea_dtl_t              len__dtl,
  flea_stream_read_mode_e rd_mode__e
)
{
  // TODO: OVERFLOW CHECK: (=> merge code with normal bv-append function)
  flea_dtl_t new_len__dtl  = byte_vec__pt->len__dtl + len__dtl;
  flea_dtl_t read_len__dtl = len__dtl;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_byte_vec_t__reserve(byte_vec__pt, new_len__dtl));
  FLEA_CCALL(
    THR_flea_rw_stream_t__read(
      read_stream__pt,
      byte_vec__pt->data__pu8 + byte_vec__pt->len__dtl,
      &read_len__dtl,
      rd_mode__e
    )
  );
  byte_vec__pt->len__dtl += read_len__dtl;
  FLEA_THR_FIN_SEC();
}
