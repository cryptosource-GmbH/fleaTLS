/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_rw_stream__H_
#define _flea_rw_stream__H_

#include "flea/types.h"
#include "flea/filter.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: provide non-blocking interface
typedef flea_err_t (*flea_rw_stream_write_f)(void *custom_obj__pv, const flea_u8_t *source_buffer__pcu8, flea_dtl_t nb_bytes_to_write__dtl);
typedef flea_err_t (*flea_rw_stream_read_f)(void *custom_obj__pv, flea_u8_t *target_buffer__pcu8, flea_dtl_t *nb_bytes_to_read__pdtl, flea_bool_t force_read__b);

typedef flea_err_t (*flea_rw_stream_open_f)(void *custom_obj__pv);
typedef flea_err_t (*flea_rw_stream_flush_write_f)(void *custom_obj__pv);
typedef void (*flea_rw_stream_close_f)(void *custom_obj__pv);

typedef struct
{
  void                         *custom_obj__pv;
  flea_rw_stream_open_f        open_func__f;
  flea_rw_stream_close_f       close_func__f;
  flea_rw_stream_read_f        read_func__f;
  flea_rw_stream_write_f       write_func__f;
  flea_rw_stream_flush_write_f flush_write_func__f;

  flea_filter_t                *filt__pt;
  flea_u8_t                    *filt_proc_buf__pu8;
  flea_al_u16_t                filt_proc_buf_len__alu16;
} flea_rw_stream_t;

#define flea_rw_stream_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))
#define flea_rw_stream_t__INIT_VALUE { .custom_obj__pv = NULL }

void flea_rw_stream_t__dtor(flea_rw_stream_t *stream__pt);

flea_err_t THR_flea_rw_stream_t__ctor(
  flea_rw_stream_t             *stream__pt,
  void                         *custom_obj__pv,
  flea_rw_stream_open_f        open_func_mbn__f,
  flea_rw_stream_close_f       close_func_mbn__f,
  flea_rw_stream_read_f        read_func_mbn__f,
  flea_rw_stream_write_f       write_func_mbn__f,
  flea_rw_stream_flush_write_f flush_write_func_mbn__f);

flea_err_t THR_flea_rw_stream_t__set_filter(flea_rw_stream_t *stream__pt, flea_filter_t *filt__pt, flea_u8_t *process_buf__pu8, flea_al_u16_t process_buf_len__alu16);

void flea_rw_stream_t__unset_filter(flea_rw_stream_t *stream__pt);

flea_err_t THR_flea_rw_stream_t__write(flea_rw_stream_t *stream__pt, const flea_u8_t *data__pcu8, flea_dtl_t data_len__dtl);

flea_err_t THR_flea_rw_stream_t__write_byte(flea_rw_stream_t *stream__pt, flea_u8_t byte__u8);

flea_err_t THR_flea_rw_stream_t__write_u32_be(flea_rw_stream_t *stream__pt, flea_u32_t value__u32, flea_al_u8_t enc_len__alu8);

flea_err_t THR_flea_rw_stream_t__flush_write(flea_rw_stream_t *stream__pt);

flea_err_t THR_flea_rw_stream_t__read(flea_rw_stream_t *stream__pt, flea_u8_t *data__pu8, flea_dtl_t *data_len__pdtl);

flea_err_t THR_flea_rw_stream_t__force_read(flea_rw_stream_t *stream__pt, flea_u8_t *data__pcu8, flea_dtl_t data_len__dtl);

void flea_rw_stream_t__set_filter(flea_rw_stream_t *stream__pt, flea_filter_t *filt__pt, flea_u8_t *process_buf__pu8, flea_al_u16_t process_buf_len__alu16);

void flea_rw_stream_t__unset_filter(flea_rw_stream_t *stream__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
