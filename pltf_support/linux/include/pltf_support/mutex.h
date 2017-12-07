#ifndef _flea_mutex__H_
#define _flea_mutex__H_

#include <pthread.h>

/**
 * platfrom independent
 */
#define FLEA_PLTFIF_DECL_MUTEX(__mutex_name)        FLEA_PLTFIF_MUTEX_TYPE __mutex_name

#define FLEA_PLTFIF_DECL_STATIC_MUTEX(__mutex_name) static FLEA_PLTFIF_DECL_MUTEX(__mutex_name)


/**
 * platfrom dependent
 */

#define FLEA_PLTFIF_MUTEX_TYPE pthread_mutex_t

#define THR_FLEA_PLTFIF_INIT_MUTEX(__mutex_ptr) \
  (0 == \
  pthread_mutex_init(__mutex_ptr, NULL) ? FLEA_ERR_FINE : FLEA_ERR_MUTEX_INIT)

/**
 * return value ignored. pthread only indicates an error here if a locked mutex
 * is destroyed.
 **/
#define FLEA_PLTFIF_DESTR_MUTEX(__mutex_ptr) pthread_mutex_destroy(__mutex_ptr)

#define THR_FLEA_PLTFIF_LOCK_MUTEX(__mutex_ptr) \
  (0 == \
  pthread_mutex_lock(__mutex_ptr) ? FLEA_ERR_FINE : FLEA_ERR_MUTEX_LOCK)

#define THR_FLEA_PLTFIF_UNLOCK_MUTEX(__mutex_ptr) \
  (0 == \
  pthread_mutex_unlock(__mutex_ptr) ? FLEA_ERR_FINE : FLEA_ERR_MUTEX_LOCK)

#endif /* h-guard */
