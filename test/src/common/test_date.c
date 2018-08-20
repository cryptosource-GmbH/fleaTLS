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
  /*const flea_u32_t seconds_of_1_day__u32    = 24 * 3600;
  const flea_u32_t seconds_of_365_days__u32 = 365 * seconds_of_1_day__u32; // 31536000;
  flea_gmt_time_t date__t;
  flea_gmt_time_t date_base__t;
  flea_gmt_time_t expected_date__t;
  const flea_u32_t add_secs_1 = 30 * seconds_of_1_day__u32;
  const flea_u32_t add_secs_2 = seconds_of_365_days__u32 + 1;
  flea_s32_t diff_exp_0__s32, diff_base_to_date__s32, diff_date_to_base__s32;*/
  FLEA_THR_BEG_FUNC();
  flea_gmt_time_t date__t = *initial_date__pt;
  flea_s32_t diff_exp_0__s32, diff_base_to_date__s32, diff_date_to_base__s32;


  flea_gmt_time_t__add_seconds_to_date(&date__t, add_secs__s32);

  if(0 != flea_asn1_cmp_utc_time(&date__t, expected_date__pt))
  {
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

#if 0
  date__t.year    = 2004;
  date__t.month   = 2;
  date__t.day     = 1;
  date__t.hours   = 0;
  date__t.minutes = 10;
  date__t.seconds = 59;

  date_base__t = date__t;
  /* 2004 has february, 29th, 2004 has 366 day */
  flea_gmt_time_t__SET_YMDhms(&expected_date__t, 2005, 1, 31, 0, 11, 0);

  flea_gmt_time_t__add_seconds_to_date(&date__t, add_secs_2);


  if(0 != flea_asn1_cmp_utc_time(&date__t, &expected_date__t))
  {
    FLEA_THROW("error in date addition", FLEA_ERR_FAILED_TEST);
  }

# ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER
  diff_exp_0__s32        = flea_gmt_time_t__diff_secs(&date__t, &expected_date__t);
  diff_date_to_base__s32 = flea_gmt_time_t__diff_secs(&date__t, &date_base__t);
  diff_base_to_date__s32 = flea_gmt_time_t__diff_secs(&date_base__t, &date__t);
  if(0 != diff_exp_0__s32 || add_secs_2 != diff_date_to_base__s32 || -(flea_s32_t) add_secs_2 != diff_base_to_date__s32)
  {
    FLEA_DBG_PRINTF("%i %u %i %i\n", diff_exp_0__s32, add_secs_2, diff_date_to_base__s32, diff_base_to_date__s32);
    FLEA_THROW("error in date diff", FLEA_ERR_FAILED_TEST);
  }
# endif /* ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER */
#endif /* if 0 */
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_date_addition_inner */

flea_err_e THR_flea_test_date_addition()
{
  const flea_u32_t seconds_of_1_day__u32    = 24 * 3600;
  const flea_u32_t seconds_of_365_days__u32 = 365 * seconds_of_1_day__u32; // 31536000;
  flea_gmt_time_t date__t;
  flea_gmt_time_t expected_date__t;
  const flea_u32_t add_secs_1 = 30 * seconds_of_1_day__u32;
  const flea_u32_t add_secs_2 = seconds_of_365_days__u32 + 1;

  FLEA_THR_BEG_FUNC();


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
  FLEA_THR_FIN_SEC_empty();
}
