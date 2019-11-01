/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "internal/common/default.h"
#include "flea/asn1_date.h"
#include "flea/array_util.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "self_test.h"

flea_err_e THR_flea_test_date_addition()
{
  const flea_u32_t seconds_of_1_day__u32    = 24 * 3600;
  const flea_u32_t seconds_of_365_days__u32 = 365 * seconds_of_1_day__u32; // 31536000;
  flea_gmt_time_t date__t;
  flea_gmt_time_t expected_date__t;

  FLEA_THR_BEG_FUNC();


  flea_gmt_time_t__SET_YMDhms(&date__t, 2005, 1, 31, 0, 11, 0);

  flea_gmt_time_t__SET_YMDhms(&expected_date__t, 2005, 3, 2, 0, 11, 0);

  flea_gmt_time_t__add_seconds_to_date(&date__t, 30 * seconds_of_1_day__u32);

  if(0 != flea_asn1_cmp_utc_time(&date__t, &expected_date__t))
  {
    FLEA_THROW("error in date addition", FLEA_ERR_FAILED_TEST);
  }


  date__t.year    = 2004;
  date__t.month   = 2;
  date__t.day     = 1;
  date__t.hours   = 0;
  date__t.minutes = 10;
  date__t.seconds = 59;

  /* 2004 has february, 29th, 2004 has 366 day */
  flea_gmt_time_t__SET_YMDhms(&expected_date__t, 2005, 1, 31, 0, 11, 0);

  flea_gmt_time_t__add_seconds_to_date(&date__t, seconds_of_365_days__u32 + 1);

  if(0 != flea_asn1_cmp_utc_time(&date__t, &expected_date__t))
  {
    FLEA_THROW("error in date addition", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_date_addition */
