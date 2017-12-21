/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_rw_stream__H_
#define _flea_rw_stream__H_

#include "flea/types.h"
#include "flea/rw_stream_types.h"
#include "flea/byte_vec.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef flea_err_e (* flea_rw_stream_write_f)(
  void*            custom_obj__pv,
  const flea_u8_t* source_buffer__pcu8,
  flea_dtl_t       nb_bytes_to_write__dtl
);

typedef flea_err_e (* flea_rw_stream_read_f)(
  void*                   custom_obj__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e rd_mode__e
);

typedef flea_err_e (* flea_rw_stream_open_f)(void* custom_obj__pv);

typedef flea_err_e (* flea_rw_stream_flush_write_f)(void* custom_obj__pv);

typedef void (* flea_rw_stream_close_f)(void* custom_obj__pv);

typedef struct
{
  void*                        custom_obj__pv;
  flea_rw_stream_open_f        open_func__f;
  flea_rw_stream_close_f       close_func__f;
  flea_rw_stream_read_f        read_func__f;
  flea_rw_stream_write_f       write_func__f;
  flea_rw_stream_flush_write_f flush_write_func__f;

  flea_u32_t                   read_rem_len__u32;
  flea_bool_e                  have_read_limit__b;
  flea_rw_stream_type_e        strm_type__e;
} flea_rw_stream_t;

#define flea_rw_stream_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))
#define flea_rw_stream_t__INIT_VALUE {.custom_obj__pv = NULL}

void flea_rw_stream_t__dtor(flea_rw_stream_t* stream__pt);

flea_err_e THR_flea_rw_stream_t__ctor(
  flea_rw_stream_t*            stream__pt,
  void*                        custom_obj__pv,
  flea_rw_stream_open_f        open_func_mbn__f,
  flea_rw_stream_close_f       close_func_mbn__f,
  flea_rw_stream_read_f        read_func_mbn__f,
  flea_rw_stream_write_f       write_func_mbn__f,
  flea_rw_stream_flush_write_f flush_write_func_mbn__f,
  flea_u32_t                   read_limit__u32
);


flea_err_e THR_flea_rw_stream_t__ctor_detailed(
  flea_rw_stream_t*            stream__pt,
  void*                        custom_obj__pv,
  flea_rw_stream_open_f        open_func__f,
  flea_rw_stream_close_f       close_func__f,
  flea_rw_stream_read_f        read_func__f,
  flea_rw_stream_write_f       write_func__f,
  flea_rw_stream_flush_write_f flush_write_func__f,
  flea_u32_t                   read_limit__u32,
  flea_rw_stream_type_e        strm_type__e
);

flea_rw_stream_type_e flea_rw_stream_t__get_strm_type(const flea_rw_stream_t* rw_stream__pt);


flea_err_e THR_flea_rw_stream_t__write(
  flea_rw_stream_t* stream__pt,
  const flea_u8_t*  data__pcu8,
  flea_dtl_t        data_len__dtl
);

flea_err_e THR_flea_rw_stream_t__write_byte(
  flea_rw_stream_t* stream__pt,
  flea_u8_t         byte__u8
);

flea_err_e THR_flea_rw_stream_t__write_u32_be(
  flea_rw_stream_t* stream__pt,
  flea_u32_t        value__u32,
  flea_al_u8_t      enc_len__alu8
);

flea_err_e THR_flea_rw_stream_t__flush_write(flea_rw_stream_t* stream__pt);

flea_err_e THR_flea_rw_stream_t__read(
  flea_rw_stream_t*       stream__pt,
  flea_u8_t*              data__pu8,
  flea_dtl_t*             data_len__pdtl,
  flea_stream_read_mode_e rd_mode__e
);


flea_err_e THR_flea_rw_stream_t__read_full(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        data__pcu8,
  flea_dtl_t        data_len__dtl
);

flea_err_e THR_flea_rw_stream_t__skip_read(
  flea_rw_stream_t* stream__pt,
  flea_dtl_t        skip_len__dtl
);

flea_err_e THR_flea_rw_stream_t__read_byte(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        byte__pu8
);

/**
 * read a big endian encoded positive integer from the stream. The width of the integer
 * may be between one and four bytes.
 *
 * @param stream__pt the stream to read from
 * @param result__pu32 pointer to the integer which will receive the decoded
 *                value
 * @param nb_bytes__alu8 the width of the encoded integer in bytes
 */
flea_err_e THR_flea_rw_stream_t__read_int_be(
  flea_rw_stream_t* stream__pt,
  flea_u32_t*       result__pu32,
  flea_al_u8_t      nb_bytes__alu8
);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
