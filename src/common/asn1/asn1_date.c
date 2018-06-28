/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/asn1_date.h"
#include "flea/x509.h"

const int ASN1_TYPE_utc_time        = 23;
const int ASN1_TYPE_GeneralizedTime = 24;

#define ASCII_NUM_OFFSET 48

#define FLEA_HAVE_TLS_SESSION_SUPPORT
#ifdef FLEA_HAVE_TLS_SESSION_SUPPORT
static flea_u32_t add_mod_n_return_multiples(
  flea_u8_t*   io__palu16,
  flea_u32_t   a__u32,
  flea_al_u8_t mod
)
{
  flea_u32_t sum__u32 = *io__palu16 + a__u32;

  *io__palu16 = sum__u32 % mod;
  return sum__u32 / mod;
}

static flea_al_u8_t days_of_month(
  flea_al_u8_t month_1_to_12,
  flea_u16_t   year
)
{
  flea_bool_t odd_month = month_1_to_12 % 2;

  if(month_1_to_12 == 2)
  {
    if(year % 4)
    {
      return 28;
    }
    return 29;
  }
  if(month_1_to_12 <= 7)
  {
    if(odd_month)
    {
      return 31;
    }
    return 30;
  }
  if(odd_month)
  {
    return 30;
  }
  return 31;
}

void flea_gmt_time_t__add_seconds_to_date(
  flea_gmt_time_t* date__pt,
  flea_u32_t       time_span_seconds__u32
)
{
  flea_u32_t carry__u32;
  flea_al_u8_t month_days__alu8;

  carry__u32  = add_mod_n_return_multiples(&date__pt->seconds, time_span_seconds__u32, 60);
  carry__u32  = add_mod_n_return_multiples(&date__pt->minutes, carry__u32, 60);
  carry__u32  = add_mod_n_return_multiples(&date__pt->hours, carry__u32, 24);
  carry__u32 += date__pt->day;
  while(carry__u32 > (month_days__alu8 = days_of_month(date__pt->month, date__pt->year)))
  {
    carry__u32 -= month_days__alu8;
    date__pt->month++;
    if(date__pt->month > 12)
    {
      date__pt->month = 1;
      date__pt->year++;
    }
  }
  date__pt->day = carry__u32;
}

#endif /* ifdef FLEA_HAVE_TLS_SESSION_SUPPORT */
flea_err_e THR_flea_asn1_parse_gmt_time_optional(
  flea_bdec_t*     dec__t,
  flea_gmt_time_t* utctime__pt,
  flea_bool_t*     found__pb
)
{
  flea_asn1_time_type_t time_type__t;
  flea_bool_t optional_found__b = FLEA_TRUE;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(byte_vec__t, 20);

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_bdec_t__dec_date_opt(
      dec__t,
      &time_type__t,
      &byte_vec__t,
      &optional_found__b
    )
  );
  if(!optional_found__b)
  {
    *found__pb = FLEA_FALSE;
    FLEA_THR_RETURN();
  }
  FLEA_CCALL(
    THR_flea_asn1_parse_date(
      time_type__t,
      byte_vec__t.data__pu8,
      byte_vec__t.len__dtl,
      utctime__pt
    )
  );
  *found__pb = FLEA_TRUE;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_asn1_parse_gmt_time_optional */

flea_err_e THR_flea_asn1_parse_gmt_time(
  flea_bdec_t*     dec__t,
  flea_gmt_time_t* utctime__pt
)
{
  FLEA_THR_BEG_FUNC();

  flea_asn1_time_type_t time_type__t;
  flea_bool_t optional_found__b = FLEA_FALSE;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(byte_vec__t, 20);
  FLEA_CCALL(
    THR_flea_bdec_t__dec_date_opt(
      dec__t,
      &time_type__t,
      &byte_vec__t,
      &optional_found__b
    )
  );

  FLEA_CCALL(
    THR_flea_asn1_parse_date(
      time_type__t,
      byte_vec__t.data__pu8,
      byte_vec__t.len__dtl,
      utctime__pt
    )
  );

  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&byte_vec__t);
  );
} /* THR_flea_asn1_parse_gmt_time */

flea_err_e THR_flea_asn1_parse_date(
  flea_asn1_time_type_t tag__t,
  const flea_u8_t*      value_in,
  flea_dtl_t            value_length,
  flea_gmt_time_t*      value_out
)
{
  FLEA_THR_BEG_FUNC();

  if(tag__t == flea_asn1_utc_time)
  {
    FLEA_CCALL(THR_flea_asn1_parse_utc_time(value_in, value_length, value_out));
    FLEA_THR_RETURN();
  }
  if(tag__t == flea_asn1_generalized_time)
  {
    FLEA_CCALL(THR_flea_asn1_parse_generalized_time(value_in, value_length, value_out));
    FLEA_THR_RETURN();
  }


  FLEA_THROW("tag for time field not recognized", FLEA_ERR_ASN1_DER_UNEXP_TAG);

  FLEA_THR_FIN_SEC_empty();
}

// function that parses up to 2 digits
static void flea_asn1_dt_prs_digits_u8(
  const flea_u8_t* in,
  flea_u8_t        length,
  flea_u8_t*       out
)
{
  *out = 0;
  flea_u16_t tmp;
  for(int i = 0; i < length; i++)
  {
    tmp = (in[i] - ASCII_NUM_OFFSET);

    for(int j = 0; j < (length - i - 1); j++)
    {
      tmp *= 10;
    }
    *out += tmp;
  }
}

// function that parses up to 4 digits
static void flea_asn1_dt_prs_digits_u16(
  const flea_u8_t* in,
  flea_u8_t        length,
  flea_u16_t*      out
)
{
  *out = 0;
  flea_u16_t tmp;
  for(int i = 0; i < length; i++)
  {
    tmp = (in[i] - ASCII_NUM_OFFSET);

    for(int j = 0; j < (length - i - 1); j++)
    {
      tmp *= 10;
    }
    *out += tmp;
  }
}

/**
 * RFC 5280
 * For the purposes of this profile, GeneralizedTime values MUST be
 * expressed in Greenwich Mean Time (Zulu) and MUST include seconds
 * (i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
 * is zero.  GeneralizedTime values MUST NOT include fractional seconds.
 */
flea_err_e THR_flea_asn1_parse_generalized_time(
  const flea_u8_t* value_in,
  size_t           value_length,
  flea_gmt_time_t* value_out
)
{
  const unsigned char* v = value_in;

  FLEA_THR_BEG_FUNC();

  if(value_length != 15)
  {
    FLEA_THROW("invalid length", FLEA_ERR_ASN1_DER_DEC_ERR);
  }

  if(v[14] != 'Z')
  {
    FLEA_THROW("invalid character", FLEA_ERR_ASN1_DER_DEC_ERR);
  }

  for(flea_u8_t i = 0; i < 14; i++)
  {
    if(v[i] > 0x39 || v[i] < 0x30)
    {
      FLEA_THROW("invalid character", FLEA_ERR_ASN1_DER_DEC_ERR);
    }
  }

  memset(value_out, 0, sizeof(flea_gmt_time_t));

  flea_asn1_dt_prs_digits_u16(v, 4, &value_out->year);
  flea_asn1_dt_prs_digits_u8(v + 4, 2, &value_out->month);
  flea_asn1_dt_prs_digits_u8(v + 6, 2, &value_out->day);
  flea_asn1_dt_prs_digits_u8(v + 8, 2, &value_out->hours);
  flea_asn1_dt_prs_digits_u8(v + 10, 2, &value_out->minutes);
  flea_asn1_dt_prs_digits_u8(v + 12, 2, &value_out->seconds);


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_asn1_parse_generalized_time */

/**
 * RFC 5280
 * For the purposes of this profile, UTCTime values MUST be expressed in
 * Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
 * YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
 * systems MUST interpret the year field (YY) as follows:
 *
 * Where YY is greater than or equal to 50, the year SHALL be
 *    interpreted as 19YY; and
 *
 *  Where YY is less than 50, the year SHALL be interpreted as 20YY.
 */
flea_err_e THR_flea_asn1_parse_utc_time(
  const flea_u8_t* value_in,
  size_t           value_length,
  flea_gmt_time_t* value_out
)
{
  const unsigned char* v = value_in;

  FLEA_THR_BEG_FUNC();

  if(value_length != 13)
    FLEA_THROW("invalid length", FLEA_ERR_ASN1_DER_DEC_ERR);

  if(v[12] != 'Z')
    FLEA_THROW("invalid character", FLEA_ERR_ASN1_DER_DEC_ERR);

  for(flea_u8_t i = 0; i < 12; i++)
  {
    if(v[i] > 0x39 || v[i] < 0x30)
      FLEA_THROW("invalid character", FLEA_ERR_ASN1_DER_DEC_ERR);
  }

  memset(value_out, 0, sizeof(flea_gmt_time_t));

  flea_asn1_dt_prs_digits_u16(v, 2, &value_out->year);
  flea_asn1_dt_prs_digits_u8(v + 2, 2, &value_out->month);
  flea_asn1_dt_prs_digits_u8(v + 4, 2, &value_out->day);
  flea_asn1_dt_prs_digits_u8(v + 6, 2, &value_out->hours);
  flea_asn1_dt_prs_digits_u8(v + 8, 2, &value_out->minutes);
  flea_asn1_dt_prs_digits_u8(v + 10, 2, &value_out->seconds);

  // set century for utc_time as specified in RFC 5280
  if(value_out->year >= 50)
    value_out->year += 1900;
  else
    value_out->year += 2000;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_asn1_parse_utc_time */

// -1: date1 < date2
// 0: equal
// 1: date1 > date2
int flea_asn1_cmp_utc_time(
  const flea_gmt_time_t* date1,
  const flea_gmt_time_t* date2
)
{
  if(date1->year > date2->year)
  {
    return 1;
  }
  else if(date1->year < date2->year)
  {
    return -1;
  }

  if(date1->month > date2->month)
  {
    return 1;
  }
  else if(date1->month < date2->month)
  {
    return -1;
  }

  if(date1->day > date2->day)
  {
    return 1;
  }
  else if(date1->day < date2->day)
  {
    return -1;
  }

  if(date1->hours > date2->hours)
  {
    return 1;
  }
  else if(date1->hours < date2->hours)
  {
    return -1;
  }

  if(date1->minutes > date2->minutes)
  {
    return 1;
  }
  else if(date1->minutes < date2->minutes)
  {
    return -1;
  }

  if(date1->seconds > date2->seconds)
  {
    return 1;
  }
  else if(date1->seconds < date2->seconds)
  {
    return -1;
  }

  return 0;
} /* flea_asn1_cmp_utc_time */
