/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/rw_stream.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"
#include "flea/alloc.h"
#include "internal/common/rw_stream_int.h"

flea_err_e THR_flea_rw_stream_t__ctor(
  flea_rw_stream_t*            stream__pt,
  void*                        custom_obj__pv,
  flea_rw_stream_open_f        open_func__f,
  flea_rw_stream_close_f       close_func__f,
  flea_rw_stream_read_f        read_func__f,
  flea_rw_stream_write_f       write_func__f,
  flea_rw_stream_flush_write_f flush_write_func__f,
  flea_u32_t                   read_limit__u32
)
{
  return THR_flea_rw_stream_t__ctor_detailed(
    stream__pt,
    custom_obj__pv,
    open_func__f,
    close_func__f,
    read_func__f,
    write_func__f,
    flush_write_func__f,
    read_limit__u32,
    flea_strm_type_generic
  );
}

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
)
{
  FLEA_THR_BEG_FUNC();
  stream__pt->custom_obj__pv      = custom_obj__pv;
  stream__pt->open_func__f        = open_func__f;
  stream__pt->close_func__f       = close_func__f;
  stream__pt->read_func__f        = read_func__f;
  stream__pt->write_func__f       = write_func__f;
  stream__pt->flush_write_func__f = flush_write_func__f;
  stream__pt->read_rem_len__u32   = read_limit__u32;
  stream__pt->have_read_limit__b  = flea_false;
  stream__pt->strm_type__e        = strm_type__e;
  if(read_limit__u32 != 0)
  {
    stream__pt->have_read_limit__b = flea_true;
  }
  if(open_func__f != NULL)
  {
    FLEA_CCALL(open_func__f(custom_obj__pv));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_rw_stream_type_e flea_rw_stream_t__get_strm_type(const flea_rw_stream_t* rw_stream__pt)
{
  return rw_stream__pt->strm_type__e;
}

flea_err_e THR_flea_rw_stream_t__write_byte(
  flea_rw_stream_t* stream__pt,
  flea_u8_t         byte__u8
)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t cp__u8 = byte__u8;
  FLEA_CCALL(THR_flea_rw_stream_t__write(stream__pt, &cp__u8, 1));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_rw_stream_t__write_u32_be(
  flea_rw_stream_t* stream__pt,
  flea_u32_t        value__u32,
  flea_al_u8_t      enc_len__alu8
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
flea_err_e THR_flea_rw_stream_t__write(
  flea_rw_stream_t* stream__pt,
  const flea_u8_t*  data__pcu8,
  flea_dtl_t        data_len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  if(stream__pt->write_func__f == NULL)
  {
    FLEA_THROW("stream writing not supported by this stream", FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED);
  }
  FLEA_CCALL(stream__pt->write_func__f(stream__pt->custom_obj__pv, data__pcu8, data_len__dtl));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_rw_stream_t__write */

flea_err_e THR_flea_rw_stream_t__flush_write(flea_rw_stream_t* stream__pt)
{
  FLEA_THR_BEG_FUNC();
  if(stream__pt->flush_write_func__f != NULL)
  {
    FLEA_CCALL(stream__pt->flush_write_func__f(stream__pt->custom_obj__pv));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_rw_stream_t__skip_read(
  flea_rw_stream_t* stream__pt,
  flea_dtl_t        skip_len__dtl
)
{
  FLEA_DECL_BUF(skip_buf__bu8, flea_u8_t, 16);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(skip_buf__bu8, 16);
  while(skip_len__dtl)
  {
    flea_al_u8_t skip__alu8 = FLEA_MIN(16, skip_len__dtl);
    FLEA_CCALL(THR_flea_rw_stream_t__read_full(stream__pt, skip_buf__bu8, skip__alu8));
    skip_len__dtl -= skip__alu8;
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF(skip_buf__bu8);
  );
}

flea_err_e THR_flea_rw_stream_t__read_full(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        data__pu8,
  flea_dtl_t        data_len__dtl
)
{
  flea_dtl_t len__dtl = data_len__dtl;

  return THR_flea_rw_stream_t__read(stream__pt, data__pu8, &len__dtl, flea_read_full);
}

flea_err_e THR_flea_rw_stream_t__read(
  flea_rw_stream_t*       stream__pt,
  flea_u8_t*              data__pu8,
  flea_dtl_t*             data_len__pdtl,
  flea_stream_read_mode_e rd_mode__e
)
{
  FLEA_THR_BEG_FUNC();

  if(stream__pt->have_read_limit__b)
  {
    if(*data_len__pdtl && (stream__pt->read_rem_len__u32 == 0))
    {
      FLEA_THROW("no more data left in stream", FLEA_ERR_STREAM_EOF);
    }

    if(*data_len__pdtl > stream__pt->read_rem_len__u32)
    {
      if(rd_mode__e == flea_read_full)
      {
        FLEA_THROW("insufficient data left in strea", FLEA_ERR_STREAM_EOF);
      }
      if((rd_mode__e == flea_read_blocking) && !stream__pt->read_rem_len__u32)
      {
        FLEA_THROW("insufficient data left in strea", FLEA_ERR_STREAM_EOF);
      }

      *data_len__pdtl = stream__pt->read_rem_len__u32;
    }
  }

  if(stream__pt->read_func__f == NULL)
  {
    FLEA_THROW("reading not supported by this stream", FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED);
  }
  FLEA_CCALL(stream__pt->read_func__f(stream__pt->custom_obj__pv, data__pu8, data_len__pdtl, rd_mode__e));
  stream__pt->read_rem_len__u32 -= *data_len__pdtl;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_rw_stream_t__read */

flea_err_e THR_flea_rw_stream_t__read_byte(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        byte__pu8
)
{
  FLEA_THR_BEG_FUNC();
  flea_dtl_t len__dtl = 1;
  FLEA_CCALL(THR_flea_rw_stream_t__read(stream__pt, byte__pu8, &len__dtl, flea_read_full));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_rw_stream_t__read_int_be(
  flea_rw_stream_t* stream__pt,
  flea_u32_t*       result__pu32,
  flea_al_u8_t      nb_bytes__alu8
)
{
  flea_u8_t enc__au8[4];
  flea_u32_t result__u32 = 0;
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(stream__pt, enc__au8, nb_bytes__alu8));
  for(i = 0; i < nb_bytes__alu8; i++)
  {
    result__u32 <<= 8;
    result__u32  |= enc__au8[i];
  }
  *result__pu32 = result__u32;
  FLEA_THR_FIN_SEC_empty();
}

void flea_rw_stream_t__dtor(flea_rw_stream_t* stream__pt)
{
  if(stream__pt->close_func__f != NULL)
  {
    stream__pt->close_func__f(stream__pt->custom_obj__pv);
  }
}
