/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_mutex__H_
#define _flea_mutex__H_
#include "internal/common/default.h"

#ifdef FLEA_HAVE_MUTEX

/**
 * Generic mutex functions provided by client code for all four mutex operations (see flea_mutex_func_set_t below for details) for fleaTLS to use for its multithreading functionality. Each function is expected to return 0 on success and a non-zero error code otherwise.
 *
 * @param mutex pointer to the mutex to be used in the operation.
 */
typedef int (* flea_generic_mutex_f)(FLEA_MUTEX_TYPE* mutex);

/**
 * Object type holding the pointers to the four types of mutex operations to be
 * provided to the function THR_flea_lib__init() in case mutexes shall be used
 * in flea. All functions are expected to return 0 on success and a non-zero error
 * code otherwise. An exception is the destr function, the return value of which will be ignored by flea.
 *
 */
typedef struct
{
  /**
   * Function to init a mutex object before locking and unlocking it.
   */
  flea_generic_mutex_f init;

  /**
   * Function to destroy a mutex when it is no more needed. This function's
   * return value will be ignored by flea.
   */
  flea_generic_mutex_f destr;

  /**
   * Function to lock a mutex.
   */
  flea_generic_mutex_f lock;

  /**
   * Function to unlock a mutex.
   */
  flea_generic_mutex_f unlock;
} flea_mutex_func_set_t;


#endif // ifdef FLEA_HAVE_MUTEX
#endif /* h-guard */
