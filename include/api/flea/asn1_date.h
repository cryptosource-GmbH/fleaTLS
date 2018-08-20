/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_asn1_date__H_
# define _flea_asn1_date__H_

# include "internal/common/default.h"
# include "flea/error.h"
# include "flea/types.h"
# include <stdlib.h>
# include "internal/common/ber_dec.h"

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Type representing a time value in the GMT time zone.
 */
typedef struct
{
  flea_u16_t year;
  flea_u8_t  month;
  flea_u8_t  day;
  flea_u8_t  hours;
  flea_u8_t  minutes;
  flea_u8_t  seconds;
} flea_gmt_time_t;

# define flea_gmt_time_t__SET_YMDhms(__gmt_time__pt, Y, M, D, h, m, s) \
  do { \
    (__gmt_time__pt)->year    = (Y);  \
    (__gmt_time__pt)->month   = (M);  \
    (__gmt_time__pt)->day     = (D);  \
    (__gmt_time__pt)->hours   = (h);  \
    (__gmt_time__pt)->minutes = (m);  \
    (__gmt_time__pt)->seconds = (s);  \
  } while(0);

flea_err_e THR_flea_asn1_parse_gmt_time(
  flea_bdec_t*     dec__t,
  flea_gmt_time_t* utctime__pt
);

flea_err_e THR_flea_asn1_parse_gmt_time_optional(
  flea_bdec_t*     dec__t,
  flea_gmt_time_t* utctime__pt,
  flea_bool_t*     found__pb
);

flea_err_e THR_flea_asn1_parse_date(
  flea_asn1_time_type_t tag__t,
  const flea_u8_t*      value_in,
  flea_dtl_t            value_length,
  flea_gmt_time_t*      value_out
);

flea_err_e THR_flea_asn1_parse_generalized_time(
  const flea_u8_t* value_in,
  size_t           value_length,
  flea_gmt_time_t* value_out
);

flea_err_e THR_flea_asn1_parse_utc_time(
  const flea_u8_t* value_in,
  size_t           value_length,
  flea_gmt_time_t* value_out
);

int flea_asn1_cmp_utc_time(
  const flea_gmt_time_t* date1,
  const flea_gmt_time_t* date2
);


void flea_gmt_time_t__add_seconds_to_date(
  flea_gmt_time_t* date__pt,
  flea_u32_t       time_span_seconds__u32
);


# ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER
flea_s32_t flea_gmt_time_t__diff_secs(
  const flea_gmt_time_t* date1,
  const flea_gmt_time_t* date2
);
# endif // ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
