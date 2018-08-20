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
  THR_flea_lib__get_gmt_time_now(&tmr__pt->start_time__t);
}

flea_u32_t flea_timer_t__get_elapsed_microsecs(flea_timer_t* tmr__pt)
{
  flea_gmt_time_t end__t;

  THR_flea_lib__get_gmt_time_now(&end__t);
  return 1000 * flea_gmt_time_t__diff_secs(&end__t, &tmr__pt->start_time__t);
}

flea_u32_t flea_timer_t__get_resolution_in_microsecs(void)
{
  return 1000;
}

#endif /* ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER */
