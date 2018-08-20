/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/asn1_date.h"
#include "flea/array_util.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "self_test.h"

static flea_err_e THR_flea_test_date_addition_inner(
  const flea_gmt_time_t* initial_date__pt,
  const flea_gmt_time_t* expected_date__pt,
  flea_s32_t             add_secs__s32
)
{
  FLEA_THR_BEG_FUNC();
  flea_gmt_time_t date__t = *initial_date__pt;
  flea_s32_t diff_exp_0__s32, diff_base_to_date__s32, diff_date_to_base__s32;


  flea_gmt_time_t__add_seconds_to_date(&date__t, add_secs__s32);

  if(0 != flea_asn1_cmp_utc_time(&date__t, expected_date__pt))
  {
    FLEA_DBG_PRINTF(
      "actual result = %02u-%02u-%02u %02u:%02u:%02u\n",
      date__t.year,
      date__t.month,
      date__t.day,
      date__t.hours,
      date__t.minutes,
      date__t.seconds
    );
    FLEA_THROW("error in date addition", FLEA_ERR_FAILED_TEST);
  }
#ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER
  diff_exp_0__s32        = flea_gmt_time_t__diff_secs(&date__t, expected_date__pt);
  diff_date_to_base__s32 = flea_gmt_time_t__diff_secs(&date__t, initial_date__pt);
  diff_base_to_date__s32 = flea_gmt_time_t__diff_secs(initial_date__pt, &date__t);
  if(0 != diff_exp_0__s32 || add_secs__s32 != diff_date_to_base__s32 ||
    -(flea_s32_t) add_secs__s32 != diff_base_to_date__s32)
  {
    FLEA_DBG_PRINTF("%i %u %i %i\n", diff_exp_0__s32, add_secs__s32, diff_date_to_base__s32, diff_base_to_date__s32);

    FLEA_THROW("error in date diff", FLEA_ERR_FAILED_TEST);
  }
#endif /* ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER */

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_date_addition_inner */

flea_err_e THR_flea_test_date_addition()
{
  typedef struct
  {
    flea_gmt_time_t initial_date__t;
    flea_gmt_time_t expected_date__t;
    flea_s32_t      add_secs__s32;
  } date_test_vec_t;

  const flea_u32_t seconds_of_1_day__u32    = 24 * 3600;
  const flea_u32_t seconds_of_365_days__u32 = 365 * seconds_of_1_day__u32; // 31536000;
  const flea_u32_t add_secs_1      = 30 * seconds_of_1_day__u32;
  const flea_u32_t add_secs_2      = seconds_of_365_days__u32 + 1;
  const date_test_vec_t test_vec[] = {
    /* get epoch:
     * $ date -d "Feb 28 1980 17:11:01" +%s */
    {{2005,  1, 31,  0, 11,  0},
      { 2005, 3, 2, 0, 11, 0},
      add_secs_1},
    {{2004,  2,  1,  0, 10, 59},
      { 2005, 1, 31, 0, 11, 0},
      add_secs_2},
    {{2004,  1,  1,  0, 10, 59},
      { 2005, 1, 31, 0, 11, 0},
      add_secs_2 + (31 * 24 * 3600)},
    {{2003, 12, 30,  0, 10, 59},
      { 2005, 1, 31, 0, 11, 0},
      add_secs_2 + ((31 + 2) * 24 * 3600)},
    {{2003, 12, 30, 13, 24, 59},
      { 2005, 1, 31, 0, 11, 0},
      add_secs_2 + ((31 + 2) * 24 * 3600) - ((13 * 60) + 14) * 60},
    {{2004,  2,  1,  0, 10, 59},
      { 2015, 1, 31, 0, 11, 0},
      add_secs_2 + 10 * seconds_of_365_days__u32 + (2 * 24 * 3600)},
    {{1970,  1,  1,  1,  0,  0},
      { 1973, 10, 21, 0, 0, 0},
      120006000},
    {{1970,  1,  1,  1,  0,  0},
      { 1973, 2, 28, 0, 22, 31},
      99703351},
    {{1970,  1,  1,  1,  0,  0},
      { 1972, 2, 29, 0, 22, 31},
      68167351},
    {{1972,  2, 29,  0, 22, 31},
      { 1980, 2, 28, 17, 11, 1},
      320602261 - 68167351},
    {{1972,  2, 29,  0, 22, 31},
      { 1980, 2, 29, 17, 11, 1},
      320688661 - 68167351},
    {{1972,  2, 29,  0, 22, 31},
      {2020, 03, 01, 1, 17, 43},
      1583021863 - 68167351}
  };

  flea_u32_t i;

  FLEA_THR_BEG_FUNC();

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(test_vec); i++)
  {
    FLEA_CCALL(
      THR_flea_test_date_addition_inner(
        &test_vec[i].initial_date__t,
        &test_vec[i].expected_date__t,
        test_vec[i].add_secs__s32
      )
    );
  }

#if 0
  flea_gmt_time_t__SET_YMDhms(&date__t, 2005, 1, 31, 0, 11, 0);


  flea_gmt_time_t__SET_YMDhms(&expected_date__t, 2005, 3, 2, 0, 11, 0);

  FLEA_CCALL(THR_flea_test_date_addition_inner(&date__t, &expected_date__t, add_secs_1));


  date__t.year    = 2004;
  date__t.month   = 2;
  date__t.day     = 1;
  date__t.hours   = 0;
  date__t.minutes = 10;
  date__t.seconds = 59;

  /* 2004 has february, 29th, 2004 has 366 day */
  flea_gmt_time_t__SET_YMDhms(&expected_date__t, 2005, 1, 31, 0, 11, 0);
  FLEA_CCALL(THR_flea_test_date_addition_inner(&date__t, &expected_date__t, add_secs_2));
#endif /* if 0 */
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_date_addition */
