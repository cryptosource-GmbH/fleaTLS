typedef struct
{
  void*                        custom_obj__pv;
  flea_rw_stream_open_f        open_func__f;
  flea_rw_stream_close_f       close_func__f;
  flea_rw_stream_read_f        read_func__f;
  flea_rw_stream_write_f       write_func__f;
  flea_rw_stream_flush_write_f flush_write_func__f;

  // flea_filter_t*               filt__pt;
  flea_u8_t*                   filt_proc_buf__pu8;
  flea_al_u16_t                filt_proc_buf_len__alu16;
  flea_u32_t                   read_rem_len__u32;
  flea_bool_t                  have_read_limit__b;
  flea_rw_stream_type_e        strm_type__e;
  // flea_bool_t                  has_filter_support__b;
} flea_rw_stream_t;

flea_err_t THR_flea_rw_stream_t__write(
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
          stream__pt->filt__pt,
          data__pcu8,
          to_go__alu16,
          stream__pt->filt_proc_buf__pu8,
          &output_len__dtl
        )
      );
      data_len__dtl -= to_go__alu16;
      data__pcu8    += to_go__alu16;
      if(output_len__dtl)
      {
        FLEA_CCALL(
          stream__pt->write_func__f(
            stream__pt->custom_obj__pv,
            stream__pt->filt_proc_buf__pu8,
            output_len__dtl
          )
        );
      }
    }
  }
  else
  {
    FLEA_CCALL(stream__pt->write_func__f(stream__pt->custom_obj__pv, data__pcu8, data_len__dtl));
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_rw_stream_t__write */

void flea_rw_stream_t__unset_filter(flea_rw_stream_t* stream__pt)
{
  stream__pt->filt__pt = NULL;
  stream__pt->filt_proc_buf__pu8       = NULL;
  stream__pt->filt_proc_buf_len__alu16 = 0;
}

flea_err_t THR_flea_rw_stream_t__set_filter(
  flea_rw_stream_t* stream__pt,
  flea_filter_t*    filt__pt,
  flea_u8_t*        process_buf__pu8,
  flea_al_u16_t     process_buf_len__alu16
)
{
  FLEA_THR_BEG_FUNC();
  if(!stream__pt->has_filter_support__b)
  {
    FLEA_THROW("cannot set filter in stream without filter support", FLEA_ERR_INV_STATE);
  }
  if(filt__pt->max_absolute_output_expansion__u16 >= process_buf_len__alu16)
  {
    FLEA_THROW("process buffer is too small for the supplied filter", FLEA_ERR_BUFF_TOO_SMALL);
  }
  stream__pt->filt__pt = filt__pt;
  stream__pt->filt_proc_buf__pu8       = process_buf__pu8;
  stream__pt->filt_proc_buf_len__alu16 = process_buf_len__alu16;
  FLEA_THR_FIN_SEC_empty();
}
