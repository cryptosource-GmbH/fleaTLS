/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_array_util_H_
#define _flea_array_util_H_

#define FLEA_SET_ARR(__dst, __val, __count) \
  memset(__dst, __val, sizeof((__dst)[0]) * (__count))

#define FLEA_CP_ARR(__dst, __src, __count) \
  memcpy(__dst, __src, sizeof((__dst)[0]) * (__count))

#define FLEA_NB_ARRAY_ENTRIES_WLEN(__arr, __size_in_bytes) ((__size_in_bytes) / sizeof((__arr)[0]))

#define FLEA_NB_ARRAY_ENTRIES(__arr)                       FLEA_NB_ARRAY_ENTRIES_WLEN((__arr), sizeof(__arr))

#endif /* h-guard */
