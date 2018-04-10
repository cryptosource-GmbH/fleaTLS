/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_rw_stream__H_
#define _flea_rw_stream__H_

#include "flea/types.h"
#include "internal/common/rw_stream_types.h"
#include "flea/byte_vec.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read modes supported by flea_rw_stream_t.
 */
typedef enum
{
  /**
   * Read operation may return with zero bytes read.
   */
  flea_read_nonblocking,

  /**
   * Read operation blocks until at least one byte has been read.
   */
  flea_read_blocking,

  /**
   * Read operation will return the exactly the requested number of bytes.
   */
  flea_read_full,
} flea_stream_read_mode_e;

/**
 * Write function type to be implemented by the client application in order to configure a
 * flea_rw_stream_t. A flea_rw_stream_t will call this function whenever it
 * writes data to the underlying data sink. The function may buffer data fed to
 * it internally before actually writing it to the underlying data sink. In this
 * case the r/w stream object must also receive a flush function which enforces
 * the writing of all pending data to the underlying data sink.
 *
 * @param [in,out] custom_obj pointer to a custom object which is always handed to the
 * write function and any other custom function supplied to the r/w stream object. It can be used for state management.
 * @param [in] source_buffer The data that the write function is supposed to write.
 * @param [in] source_buffer_len The length of the data that is supposed to be
 * written.
 *
 * @return an error code
 */
typedef flea_err_e (* flea_rw_stream_write_f)(
  void*            custom_obj,
  const flea_u8_t* source_buffer,
  flea_dtl_t       source_buffer_len
);

/**
 * Read function type to be implemented by the client application in order to configure a
 * flea_rw_stream_t. A flea_rw_stream_t will call this function whenever it
 * reads data from the underlying data source.
 *
 * @param [in,out] custom_obj pointer to a custom object which is always handed to the
 * read function and any other custom function supplied to the r/w stream object.
 * It can be used for state management.
 * @param [out] target_buffer The buffer where the read function writes the read
 * stream data to.
 * @param [in,out] nb_bytes_to_read Upon input, this parameter holds the number
 * of bytes requested from the read function. On function return, it receives
 * the number of actually read bytes that have been written to target_buffer. Depending on the parameter
 * read_mode, the function may return less data than requested.
 *
 * @return an error code
 */
typedef flea_err_e (* flea_rw_stream_read_f)(
  void*                   custom_obj,
  flea_u8_t*              target_buffer,
  flea_dtl_t*             nb_bytes_to_read,
  flea_stream_read_mode_e read_mode
);

/**
 * Open function type to be implemented by the client application in order to configure a
 * flea_rw_stream_t. A flea_rw_stream_t will call this function when it is
 * created. Supplying an open function is optional.
 *
 * @param [in,out] custom_obj pointer to a custom object which is always handed to the
 * open function and any other custom function supplied to the r/w stream object.
 * It can be used for state management.
 *
 * @return an error code
 */
typedef flea_err_e (* flea_rw_stream_open_f)(void* custom_obj);

/**
 * Flush write function type to be implemented by the client application in order to configure a
 * flea_rw_stream_t. A flea_rw_stream_t will call this function whenever it
 * flushes out potentially pending write data to the underlying data sink. If
 * the supplied custom write function is not guaranteed to always write all data
 * to the underlying data sink, then this function must force the writing of all
 * pending write data in the flea_rw_stream_t object.
 *
 * @param [in,out] custom_obj pointer to a custom object which is always handed to the
 * flush write function and any other custom function supplied to the rw_stream
 * object. It can be used for state management.
 *
 * @return an error code
 */
typedef flea_err_e (* flea_rw_stream_flush_write_f)(void* custom_obj);

/**
 * Close function type to be implemented by the client application in order to configure a
 * flea_rw_stream_t. A flea_rw_stream_t will call this function when it is
 * destroyed.
 *
 * @param [in,out] custom_obj pointer to a custom object which is always handed to the
 * close function and any other custom function supplied to the r/w stream object.
 * It can be used for state management.
 *
 * @return an error code
 */
typedef void (* flea_rw_stream_close_f)(void* custom_obj);

/**
 * Generic read/write stream type. It is configured with caller-defined functions. It may support both read and write operations or only one of the two.
 */
typedef struct
{
  void*                        custom_obj__pv;
  flea_rw_stream_open_f        open_func__f;
  flea_rw_stream_close_f       close_func__f;
  flea_rw_stream_read_f        read_func__f;
  flea_rw_stream_write_f       write_func__f;
  flea_rw_stream_flush_write_f flush_write_func__f;

  flea_u32_t                   read_rem_len__u32;
  flea_bool_t                  have_read_limit__b;
  flea_rw_stream_type_e        strm_type__e;
} flea_rw_stream_t;

/**
 * Init a read/write stream object.
 *
 * @param stream Pointer to the r/w stream object to init.
 */
#define flea_rw_stream_t__INIT(stream) memset((stream), 0, sizeof(*(stream)))

/**
 * Initialization value for an r/w stream object.
 */
#define flea_rw_stream_t__INIT_VALUE {.custom_obj__pv = NULL}


/**
 * Determine whether the r/w stream has a read length limit.
 */
#define flea_rw_stream_t__HAVE_READ_LIMIT(stream) (((stream)->have_read_limit__b) ? FLEA_TRUE : FLEA_FALSE)

/**
 * Determine the remaining read length in the case that the stream has a read
 * length limit.
 */
#define flea_rw_stream_t__GET_REM_READ_LEN(stream) ((stream)->read_rem_len__u32 ? (stream)->read_rem_len__u32 : 0)

/**
 * Determine whether the r/w stream has a read length limit.
 */
#define flea_rw_stream_t__HAVE_READ_LIMIT(stream) (((stream)->have_read_limit__b) ? FLEA_TRUE : FLEA_FALSE)

/**
 * Determine the remaining read length in the case that the stream has a read
 * length limit.
 */
#define flea_rw_stream_t__GET_REM_READ_LEN(stream) ((stream)->read_rem_len__u32 ? (stream)->read_rem_len__u32 : 0)

/**
 * Destroy an r/w stream.
 *
 * @param stream the r/w stream object to destroy.
 */
void flea_rw_stream_t__dtor(flea_rw_stream_t* stream);

/**
 * Create a read/write stream object.
 *
 * @param stream A pointer to the r/w stream object to create.
 * @param custom_obj Pointer to a custom object which is handed over to any of the custom
 * functions supplied in the further parameters whenever they are called by the
 * r/w stream object.
 * @param open_func_mbn The function for opening the underlying data source and
 * sink used by this r/w stream. It may be supplied as null, in which the
 * opening of the resources must have already happened before this ctor is
 * called.
 * @param close_func_mbn If specified as non-null, then this function is called when the r/w stream's dtor is
 * called.
 * @param read_func_mbn This function implements the reading of data from the
 * underlying data source. If it is supplied as null, then this r/w stream
 * object does not support reading functionality and will return an error code if
 * read functions are called on it.
 * @param write_func_mbn This function implements the writing of data from the
 * underlying data source. If it is supplied as null, then this r/w stream
 * object does not support writing functionality and will return an error code if
 * write functions are called on it.
 * @param flush_write_func_mbn This function must enforce the writing of any
 * pending write data that was supplied to the write function. If the r/w stream
 * shall not support writing functionality, or the supplied write
 * function does not implement the buffering of write data, then this function may be supplied as null.
 * @param read_limit The r/w stream will indicate refuse to output further data
 * when the number of bytes specified by this value have been read from it. If
 * this value is specified as zero, then no read limit will be applied.
 *
 */
flea_err_e THR_flea_rw_stream_t__ctor(
  flea_rw_stream_t*            stream,
  void*                        custom_obj,
  flea_rw_stream_open_f        open_func_mbn,
  flea_rw_stream_close_f       close_func_mbn,
  flea_rw_stream_read_f        read_func_mbn,
  flea_rw_stream_write_f       write_func_mbn,
  flea_rw_stream_flush_write_f flush_write_func_mbn,
  flea_u32_t                   read_limit
);

/**
 * Write data to an r/w stream object. The data is not necessarily written to
 * the underlying data sink, but may be buffered internally until a call to THR_flea_rw_stream_t__flush_write() is made.
 *
 * @param stream Pointer to the r/w stream object.
 * @param dta Data to write.
 * @param dta_len The length of the data to write.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__write(
  flea_rw_stream_t* stream,
  const flea_u8_t*  dta,
  flea_dtl_t        dta_len
);

/**
 * Write a byte to an r/w stream object. The data is not necessarily written to
 * the underlying data sink, but may be buffered internally until a call to THR_flea_rw_stream_t__flush_write() is made.
 *
 * @param stream Pointer to the r/w stream object.
 * @param byte The byte to write.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__write_byte(
  flea_rw_stream_t* stream,
  flea_u8_t         byte
);

/**
 * Write a numeric value in big endian byte order to an r/w stream object. The data is not necessarily written to
 * the underlying data sink, but may be buffered internally until a call to THR_flea_rw_stream_t__flush_write() is made.
 *
 * @param stream Pointer to the r/w stream object.
 * @param value The value to write.
 * @param enc_len the number bytes which are actually encoded. If the value is
 * larger than the encoding allows, it is truncated.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__write_int_be(
  flea_rw_stream_t* stream,
  flea_u32_t        value,
  flea_al_u8_t      enc_len
);

/**
 * Enforce the writing of all pending write data to the underlying data sink.
 *
 * @param stream Pointer to the r/w stream object.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__flush_write(flea_rw_stream_t* stream);

/**
 * Read data from an r/w stream object.
 *
 * @param[in,out] stream Pointer to the r/w stream object.
 * @param[out] dta The buffer to the receive the read data.
 * @param[in,out] dta_len On input, the pointer target specifies the requested read length. On function return, it receives the number of bytes that were actually written dta.
 * @param read_mode the mode in which the data is read.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__read(
  flea_rw_stream_t*       stream,
  flea_u8_t*              dta,
  flea_dtl_t*             dta_len,
  flea_stream_read_mode_e read_mode
);

/**
 * Read data from an r/w stream object with read mode \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink.
 *
 * @param[in,out] stream Pointer to the r/w stream object.
 * @param[out] dta The buffer to the receive the read data.
 * @param[in,out] dta_len On input, the pointer target specifies the requested read length. On function return, it receives the number of bytes that were actually written dta.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__read_full(
  flea_rw_stream_t* stream,
  flea_u8_t*        dta,
  flea_dtl_t        dta_len
);

/**
 * Skip input data from an r/w stream object.
 *
 * @param[in,out] stream Pointer to the r/w stream object.
 * @param[in] skip_len The number of bytes to skip.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__skip_read(
  flea_rw_stream_t* stream,
  flea_dtl_t        skip_len
);

/**
 * Read a byte from an r/w stream object with read mode \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink.
 *
 * @param[in,out] stream Pointer to the r/w stream object.
 * @param[out] result A pointer to the byte to the receive the read data.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__read_byte(
  flea_rw_stream_t* stream,
  flea_u8_t*        result
);


/**
 * Read an u16 value in big endian format from an r/w stream object with read mode \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink.
 *
 * @param[in,out] stream Pointer to the r/w stream object.
 * @param[out] result A pointer to the byte to the receive the read data.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__read_u16_be(
  flea_rw_stream_t* stream,
  flea_u16_t*       result
);

/**
 * Read a big endian encoded positive integer from the stream with read mode \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink. The width of the integer
 * may be between one and four bytes.
 *
 * @param stream the stream to read from
 * @param result pointer to the integer which will receive the decoded
 *                value
 * @param nb_bytes the width of the encoded integer in bytes. This many bytes
 * are read from the stream.
 *
 * @return an error code
 */
flea_err_e THR_flea_rw_stream_t__read_int_be(
  flea_rw_stream_t* stream,
  flea_u32_t*       result,
  flea_al_u8_t      nb_bytes
);

/**
 * Transfer data from a source read-stream to a destination write-stream.
 * The reads are performed in non-blocking read mode until either an error on
 * the read stream occurs or the non-blocking read returns zero bytes. The
 * function does *not* call flea_rw_stream_t__flush_write() on the destination
 * write-stream.
 *
 *
 * @param [in,out] source the stream to read from
 * @param [in,out] dest the stream to write to
 * @param [in,out] transfer_length on function call, this must hold the number of bytes request to be transferred. On function exit, this holds the number of actually transferred bytes.
 * @param [in] buffer  a workspace buffer to be used by the function. The larger
 * the buffer, the more efficient the function will work
 * @param [in] buffer_len the length of buffer
 * @param [out]  result_read_strm_err if an error occurred on the read stream,
 * this holds the corresponding error code. If no error occurred, this receives
 * the value FLEA_ERR_FINE.
 *
 * @return an error code
 *
 */
flea_err_e THR_flea_rw_stream_t__pump(
  flea_rw_stream_t* source,
  flea_rw_stream_t* dest,
  flea_dtl_t*       transfer_length,
  flea_u8_t*        buffer,
  flea_dtl_t        buffer_len,
  flea_err_e*       result_read_strm_err
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
