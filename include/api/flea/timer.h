#ifndef _flea_timer__H_
#define _flea_timer__H_

#include "internal/common/default.h"
#include "flea/asn1_date.h"

#ifdef FLEA_HAVE_TIMER

# ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER

typedef struct
{
  flea_gmt_time_t start_time__t;
} flea_wall_clock_timer_t;

typedef flea_wall_clock_timer_t flea_timer_t;
# endif // ifdef FLEA_USE_WALL_CLOCK_BASED_TIMER

# define flea_timer_t__INIT(ptr) FLEA_ZERO_STRUCT(ptr)

/**
 * Create a timer object.
 *
 * @param tmr__pt Pointer to the timer object.
 */
flea_err_e THR_flea_timer_t__ctor(flea_timer_t* tmr__pt);

/**
 * Destroy a timer object.
 *
 * @param tmr__pt Pointer to the timer object.
 */
void flea_timer_t__dtor(flea_timer_t* tmr__pt);

/**
 * Start a new time measurement.
 *
 * @param tmr__pt Pointer to the timer object.
 */
void flea_timer_t__start(flea_timer_t* tmr__pt);

/**
 * Return the elapsed time in microseconds in an unsigned 32 bit type. This means that the timer overflows after 24.82 days.
 * This timer is intended and used in fleaTLS only for the purpose of determining timeouts in the domain of seconds within communication protocols,
 * and thus is this restriction is acceptable for this purpose.
 *
 * @param tmr__pt Pointer to the timer object.
 *
 * @return the number of elapsed microsecs since the last call to flea_timer_t__start().
 */
flea_u32_t flea_timer_t__get_elapsed_millisecs(flea_timer_t* tmr__pt);

/**
 * Get the resolution of flea_timer_t timers in microseconds.
 *
 * @return the resolution of the timer in microseconds.
 */
flea_u32_t flea_timer_t__get_resolution_in_millisecs(void);

#endif // ifdef FLEA_HAVE_TIMER


#endif /* h-guard */
