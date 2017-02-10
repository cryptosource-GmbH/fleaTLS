/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/asn1_date.h"
#include "flea/array_util.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"

flea_u8_t flea_test_asn1_gmttime_strlen(flea_u8_t* in)
{
  flea_u8_t* p = in;
  flea_u8_t i  = 0;

  while(p[i] != 0x00)
  {
    i++;
  }

  return i;
}

flea_err_t THR_flea_test_asn1_date()
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t input[] = "910506164540Z";
  flea_dtl_t length = sizeof(input) - 1;

  flea_gmt_time_t output;

  FLEA_CCALL(THR_flea_asn1_parse_date(flea_asn1_utc_time, input, length, &output));

  if(output.year != 1991 || output.month != 5 || output.day != 6 || output.hours != 16 || output.minutes != 45 ||
    output.seconds != 40)
  {
    FLEA_THROW("parse ASN.1 utc time incorrect", FLEA_ERR_FAILED_TEST);
  }

  flea_u8_t input2[] = "19910506164540Z";
  flea_dtl_t length2 = sizeof(input2) - 1;

  flea_gmt_time_t output2;

  FLEA_CCALL(THR_flea_asn1_parse_date(flea_asn1_generalized_time, input2, length2, &output2));

  if(output2.year != 1991 || output2.month != 5 || output2.day != 6 || output2.hours != 16 || output2.minutes != 45 ||
    output2.seconds != 40)
  {
    FLEA_THROW("parse ASN.1 generalized time incorrect", FLEA_ERR_FAILED_TEST);
  }

  typedef struct
  {
    flea_u8_t* date_a;
    flea_u8_t* date_b;
    flea_s8_t  result;
  } flea_asn1_date_test_case;

  enum flea_utc_time_t_test_result { FLEA_UTCTIME_DEC_ERROR = 2, FLEA_UTCTIME_GREATER = 1, FLEA_UTCTIME_EQUAL = 0,
                                     FLEA_UTCTIME_LESS      = -1  };
  enum flea_generalized_time_t_test_result { FLEA_GENERALIZEDTIME_DEC_ERROR = 2, FLEA_GENERALIZEDTIME_GREATER = 1,
                                             FLEA_GENERALIEZDTIME_EQUAL     = 0, FLEA_GENERALIZEDTIME_LESS = -1  };

  flea_asn1_date_test_case utc_test_cases[] = {
    // old tests with offset, should all throw errors
    (flea_asn1_date_test_case){ (flea_u8_t *) "910506164540-0700",    (flea_u8_t *) "910506164540-0700",
                                FLEA_UTCTIME_DEC_ERROR},
    (flea_asn1_date_test_case){ (flea_u8_t *) "920506164540-0700",    (flea_u8_t *) "910506164540-0700",FLEA_UTCTIME_DEC_ERROR },

    (flea_asn1_date_test_case){ (flea_u8_t *) "160228200000-0000",    (flea_u8_t *) "1602282000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "160228200000-0100",    (flea_u8_t *) "1602282100Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "160228200000-0400",    (flea_u8_t *) "1602290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "170228200000-5500",    (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "abq228200000-0000",    (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "17022820000-5500",     (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "170228200000-00",      (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "170228200000-",        (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "170228200000/0000",    (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "",                     (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "1",                    (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "22",                   (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "223",                  (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "ABC170228200000-0000", (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },
    (flea_asn1_date_test_case){ (flea_u8_t *) "000000000000000-i500", (flea_u8_t *) "1702290000Z",      FLEA_UTCTIME_DEC_ERROR },

    (flea_asn1_date_test_case){ (flea_u8_t *) "490228200000Z",        (flea_u8_t *) "500228200000Z",    FLEA_UTCTIME_GREATER   }
  };

  flea_asn1_date_test_case gen_test_cases[] = {
    (flea_asn1_date_test_case){ (flea_u8_t *) "19490228200000Z", (flea_u8_t *) "19500228200000Z", FLEA_GENERALIZEDTIME_LESS}
  };


  flea_gmt_time_t date_a__t;
  flea_gmt_time_t date_b__t;
  flea_s8_t res__t;


  flea_err_t res_1__t, res_2__t;

  for(flea_u8_t i = 0; i < (sizeof(utc_test_cases) / sizeof(flea_asn1_date_test_case)); i++)
  {
    // parse dates
    res_1__t = THR_flea_asn1_parse_utc_time(utc_test_cases[i].date_a, flea_test_asn1_gmttime_strlen(utc_test_cases[i].date_a), &date_a__t);
    res_2__t = THR_flea_asn1_parse_utc_time(utc_test_cases[i].date_b, flea_test_asn1_gmttime_strlen(utc_test_cases[i].date_b), &date_b__t);

    if(res_1__t != FLEA_ERR_FINE)
    {
      if(res_1__t == FLEA_ERR_ASN1_DER_DEC_ERR && utc_test_cases[i].result == FLEA_UTCTIME_DEC_ERROR)
        continue;
      else
        FLEA_THROW("Decode error in list based tests for flea_asn1_cmp_utc_time()", FLEA_ERR_FAILED_TEST);
    }
    if(res_2__t != FLEA_ERR_FINE)
    {
      if(res_2__t == FLEA_ERR_ASN1_DER_DEC_ERR && utc_test_cases[i].result == FLEA_UTCTIME_DEC_ERROR)
        continue;
      else
        FLEA_THROW("Decode error in list based tests for flea_asn1_cmp_utc_time()", FLEA_ERR_FAILED_TEST);
    }

    // compare dates
    res__t = flea_asn1_cmp_utc_time(&date_a__t, &date_b__t);

    // check result
    if(res__t != utc_test_cases[i].result)
    {
      FLEA_THROW("Unexpected result in list based tests for flea_asn1_cmp_utc_time()", FLEA_ERR_FAILED_TEST);
    }
  }


  for(flea_u8_t i = 0; i < (sizeof(gen_test_cases) / sizeof(flea_asn1_date_test_case)); i++)
  {
    // parse dates
    res_1__t = THR_flea_asn1_parse_generalized_time(gen_test_cases[i].date_a, flea_test_asn1_gmttime_strlen(gen_test_cases[i].date_a), &date_a__t);
    res_2__t = THR_flea_asn1_parse_generalized_time(gen_test_cases[i].date_b, flea_test_asn1_gmttime_strlen(gen_test_cases[i].date_b), &date_b__t);

    if(res_1__t != FLEA_ERR_FINE)
    {
      if(res_1__t == FLEA_ERR_ASN1_DER_DEC_ERR && gen_test_cases[i].result == FLEA_UTCTIME_DEC_ERROR)
        continue;
      else
        FLEA_THROW("Decode error in list based tests for flea_asn1_cmp_utc_time()", FLEA_ERR_FAILED_TEST);
    }
    if(res_2__t != FLEA_ERR_FINE)
    {
      if(res_2__t == FLEA_ERR_ASN1_DER_DEC_ERR && gen_test_cases[i].result == FLEA_UTCTIME_DEC_ERROR)
        continue;
      else
        FLEA_THROW("Decode error in list based tests for flea_asn1_cmp_utc_time()", FLEA_ERR_FAILED_TEST);
    }

    // compare dates
    res__t = flea_asn1_cmp_utc_time(&date_a__t, &date_b__t);

    // check result
    if(res__t != gen_test_cases[i].result)
    {
      FLEA_THROW("Unexpected result in list based tests for flea_asn1_cmp_utc_time()", FLEA_ERR_FAILED_TEST);
    }
  }


  FLEA_THR_FIN_SEC();
} /* THR_flea_test_asn1_date */
