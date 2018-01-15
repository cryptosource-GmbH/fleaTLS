/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_hostn_ver__H_
#define _flea_hostn_ver__H_

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/x509.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type of hostname.
 */
typedef enum
{
  /**
   * IP address.
   */
  flea_host_ipaddr,

  /**
   * DNS name.
   */
  flea_host_dnsname
} flea_host_id_type_e;


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
