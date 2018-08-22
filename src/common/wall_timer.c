#include "flea/timer.h"
#include "internal/common/lib_int.h"

#ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER


flea_err_e THR_flea_timer_t__ctor(flea_timer_t* tmr__pt)
{
  return FLEA_ERR_FINE;
}

void flea_timer_t__dtor(flea_timer_t* tmr__pt)
{ }

void flea_timer_t__start(flea_timer_t* tmr__pt)
{
  // TODO: will become a non-thrower
  flea_err_e dummy;
  flea_err_e ignore = THR_flea_lib__get_gmt_time_now(&tmr__pt->start_time__t);

  dummy  = ignore;
  ignore = dummy;
}

flea_u32_t flea_timer_t__get_elapsed_millisecs(flea_timer_t* tmr__pt)
{
  flea_gmt_time_t end__t;

  flea_err_e dummy;
  flea_err_e ignore = THR_flea_lib__get_gmt_time_now(&end__t);

  dummy  = ignore;
  ignore = dummy;
  return 1000 * flea_gmt_time_t__diff_secs(&end__t, &tmr__pt->start_time__t);
}

flea_u32_t flea_timer_t__get_resolution_in_millisecs(void)
{
  return 1000;
}

#endif /* ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER */
