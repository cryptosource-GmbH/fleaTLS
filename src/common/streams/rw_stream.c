/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/rw_stream.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"
#include "flea/filter.h"

flea_err_t THR_flea_rw_stream_t__ctor(
  flea_rw_stream_t             *stream__pt,
  void                         *custom_obj__pv,
  flea_rw_stream_open_f        open_func__f,
  flea_rw_stream_close_f       close_func__f,
  flea_rw_stream_read_f        read_func__f,
  flea_rw_stream_write_f       write_func__f,
  flea_rw_stream_flush_write_f flush_write_func__f
)
{
  FLEA_THR_BEG_FUNC();
  stream__pt->custom_obj__pv      = custom_obj__pv;
  stream__pt->open_func__f        = open_func__f;
  stream__pt->close_func__f       = close_func__f;
  stream__pt->read_func__f        = read_func__f;
  stream__pt->write_func__f       = write_func__f;
  stream__pt->flush_write_func__f = flush_write_func__f;
  stream__pt->filt__pt = NULL;
  stream__pt->filt_proc_buf__pu8       = NULL;
  stream__pt->filt_proc_buf_len__alu16 = 0;
  if(open_func__f != NULL)
  {
    FLEA_CCALL(open_func__f(custom_obj__pv));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__set_filter(
  flea_rw_stream_t *stream__pt,
  flea_filter_t    *filt__pt,
  flea_u8_t        *process_buf__pu8,
  flea_al_u16_t    process_buf_len__alu16
)
{
  FLEA_THR_BEG_FUNC();
  if(filt__pt->max_absolute_output_expansion__u16 >= process_buf_len__alu16)
  {
    FLEA_THROW("process buffer is too small for the supplied filter", FLEA_ERR_BUFF_TOO_SMALL);
  }
  stream__pt->filt__pt = filt__pt;
  stream__pt->filt_proc_buf__pu8       = process_buf__pu8;
  stream__pt->filt_proc_buf_len__alu16 = process_buf_len__alu16;
  FLEA_THR_FIN_SEC_empty();
}

void flea_rw_stream_t__unset_filter(flea_rw_stream_t *stream__pt)
{
  stream__pt->filt__pt = NULL;
  stream__pt->filt_proc_buf__pu8       = NULL;
  stream__pt->filt_proc_buf_len__alu16 = 0;
}

flea_err_t THR_flea_rw_stream_t__write_byte(flea_rw_stream_t *stream__pt, flea_u8_t byte__u8)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t cp__u8 = byte__u8;
  FLEA_CCALL(THR_flea_rw_stream_t__write(stream__pt, &cp__u8, 1));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__write_u32_be(
  flea_rw_stream_t *stream__pt,
  flea_u32_t       value__u32,
  flea_al_u8_t     enc_len__alu8
)
{
  flea_u8_t enc__au8[4];

  FLEA_THR_BEG_FUNC();
  if(enc_len__alu8 > 4)
  {
    enc_len__alu8 = 4;
  }
  flea__encode_U32_BE(value__u32, enc__au8);
  FLEA_CCALL(THR_flea_rw_stream_t__write(stream__pt, enc__au8 + (4 - enc_len__alu8), enc_len__alu8));
  FLEA_THR_FIN_SEC_empty();
}

/* write blocking */
flea_err_t THR_flea_rw_stream_t__write(
  flea_rw_stream_t *stream__pt,
  const flea_u8_t  *data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  if(stream__pt->write_func__f == NULL)
  {
    FLEA_THROW("stream writing not supported by this stream", FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED);
  }
  if(stream__pt->filt__pt)
  {
    const flea_dtl_t portion_size__dtl = stream__pt->filt_proc_buf_len__alu16
      - stream__pt->filt__pt->max_absolute_output_expansion__u16;
    while(data_len__dtl)
    {
      flea_al_u16_t to_go__alu16 = FLEA_MIN(data_len__dtl, portion_size__dtl);
      flea_dtl_t output_len__dtl = stream__pt->filt_proc_buf_len__alu16;
      FLEA_CCALL(
        THR_flea_filter_t__process(
          stream__pt->filt__pt, data__pcu8, to_go__alu16,
          stream__pt->filt_proc_buf__pu8, &output_len__dtl
        )
      );
      data_len__dtl -= to_go__alu16;
      data__pcu8    += to_go__alu16;
      if(output_len__dtl)
      {
        FLEA_CCALL(
          stream__pt->write_func__f(
            stream__pt->custom_obj__pv, stream__pt->filt_proc_buf__pu8,
            output_len__dtl
          )
        );
      }
    }
  } else
  {
    FLEA_CCALL(stream__pt->write_func__f(stream__pt->custom_obj__pv, data__pcu8, data_len__dtl));
  }
  FLEA_THR_FIN_SEC_empty();
}

#if 0
flea_err_t THR_flea_rw_stream_t__write_through_filter_and_tee_output(
  flea_rw_stream_t *stream1__pt,
  flea_rw_stream_t *stream2__pt,
  flea_filter_t    *filt__pt,
  const flea_u8_t  *data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  if(stream1__pt->write_func__f == NULL || stream2__pt->write_func__f == NULL)
  {
    FLEA_THROW("stream writing not supported by this stream", FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED);
  }
  FLEA_CCALL(stream__pt->write_func__f(stream__pt->custom_obj__pv, data__pcu8, data_len__dtl));
  FLEA_THR_FIN_SEC_empty();
}

#endif /* if 0 */

flea_err_t THR_flea_rw_stream_t__flush_write(flea_rw_stream_t *stream__pt)
{
  FLEA_THR_BEG_FUNC();
  if(stream__pt->flush_write_func__f != NULL)
  {
    FLEA_CCALL(stream__pt->flush_write_func__f(stream__pt->custom_obj__pv));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__read(flea_rw_stream_t *stream__pt, flea_u8_t *data__pu8, flea_dtl_t *data_len__pdtl)
{
  FLEA_THR_BEG_FUNC();

  if(stream__pt->filt__pt != NULL)
  {
    FLEA_THROW("FILTER NOT IMPLEMENTED FOR STREAM READING", FLEA_ERR_INV_ARG);
  }
  if(stream__pt->read_func__f == NULL)
  {
    FLEA_THROW("stream writing not supported by this stream", FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED);
  }
  FLEA_CCALL(stream__pt->read_func__f(stream__pt->custom_obj__pv, data__pu8, data_len__pdtl, FLEA_FALSE));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__force_read(
  flea_rw_stream_t *stream__pt,
  flea_u8_t        *data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  flea_dtl_t len__dtl = data_len__dtl;


  if(stream__pt->filt__pt != NULL)
  {
    FLEA_THROW("FILTER NOT IMPLEMENTED FOR STREAM READING", FLEA_ERR_INV_ARG);
  }

  if(stream__pt->read_func__f == NULL)
  {
    FLEA_THROW("stream writing not supported by this stream", FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED);
  }
  FLEA_CCALL(stream__pt->read_func__f(stream__pt->custom_obj__pv, data__pcu8, &len__dtl, FLEA_TRUE));
  FLEA_THR_FIN_SEC_empty();
}

void flea_rw_stream_t__dtor(flea_rw_stream_t *stream__pt)
{
  if(stream__pt->close_func__f != NULL)
  {
    stream__pt->close_func__f(stream__pt->custom_obj__pv);
  }
}
