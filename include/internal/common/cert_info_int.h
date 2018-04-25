/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_info__H_
#define _flea_cert_info__H_

#include "flea/x509.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
  flea_x509_cert_ref_t cert_ref__t;
  flea_byte_vec_t      ref_to_raw_der__rcu8;
  flea_byte_vec_t      ref_to_tbs__rcu8;
  flea_bool_t          is_trusted__b;
} flea_x509_cert_info_t;

#define flea_x509_cert_info_t__INIT(__p) memset(__p, 0, sizeof(*(__p)))

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
