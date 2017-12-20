/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_hostn_ver__H_
#define _flea_hostn_ver__H_

#include "flea/error_handling.h"
#include "flea/x509.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum { flea_host_ipaddr, flea_host_dnsname } flea_host_id_type_e;


flea_err_e THR_flea_x509__verify_tls_server_id(
  const flea_byte_vec_t*      user_id__pcrcu8,
  flea_host_id_type_e         host_type,
  const flea_x509_cert_ref_t* server_cert__pt
);

flea_err_e THR_flea_x509__verify_tls_server_id_cstr(
  const char*                 user_id__cs,
  flea_host_id_type_e         host_type,
  const flea_x509_cert_ref_t* server_cert__pt
);


#ifdef __cplusplus
}
#endif


#endif /* h-guard */
