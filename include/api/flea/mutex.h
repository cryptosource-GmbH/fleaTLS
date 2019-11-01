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

/**
 * @file mutex.h
 *
 * This header file specifies the generic mutex support of fleaTLS.
 */
#ifndef _flea_mutex__H_
#define _flea_mutex__H_
#include "internal/common/default.h"

#ifdef FLEA_HAVE_MUTEX

/**
 * Generic mutex type of fleaTLS. In the shipped configuration, pthread mutexes
 * are preconfigured. Concurrency support can be enabled, disabled and
 * configured in build_config_gen.h.
 */
typedef FLEA_MUTEX_TYPE flea_mutex_t;

/**
 * Generic mutex functions provided by client code for all four mutex operations (see flea_mutex_func_set_t below for details) for fleaTLS to use for its multithreading functionality. Each function is expected to return 0 on success and a non-zero error code otherwise.
 *
 * @param mutex pointer to the mutex to be used in the operation.
 */
typedef int (* flea_generic_mutex_f)(flea_mutex_t* mutex);

/**
 * Object type holding the pointers to the four types of mutex operations to be
 * provided to the function THR_flea_lib__init() in case mutexes shall be used
 * in flea. All functions are expected to return 0 on success and a non-zero error
 * code otherwise. An exception is the destr function, the return value of which will be ignored by flea.
 *
 * The lifecycle of each mutex object in fleaTLS code is always a sequence
 * adhering to the pattern
 *
 * init
 * lock
 * unlock
 * lock
 * unlock
 * ... (further lock-unlock pairs)
 * destr
 *
 * The meaning of locking and unlocking of a mutex follows the common
 * understanding of mutex functionality.
 *
 */
typedef struct
{
  /**
   * Function to init a mutex object before starting to locking and unlocking it.
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
