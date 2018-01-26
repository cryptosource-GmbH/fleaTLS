/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_hostn_ver_int__H_
#define _flea_hostn_ver_int__H_

#include "flea/byte_vec.h"
#include "flea/hostn_ver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_host_id_type_e host_id_type__e;
  flea_ref_cu8_t      host_id__ct;
} flea_hostn_validation_params_t;

typedef struct
{
  flea_bool_t id_matched__b;
  flea_bool_t contains_ipaddr__b;
  flea_bool_t contains_dnsname__b;
} flea_hostn_match_info_t;

flea_err_e THR_flea_x509__parse_san_and_validate_hostn(
  const flea_ref_cu8_t*    user_id__pcrcu8,
  flea_host_id_type_e      host_type,
  flea_ber_dec_t*          cont_dec__pt,
  flea_byte_vec_t*         work_spc__pt,
  flea_hostn_match_info_t* match_info__pt
);

flea_err_e THR_flea_x509__verify_host_name(
  const flea_ref_cu8_t*  user_host_name__pcrcu8,
  const flea_byte_vec_t* cert_dns_name__pcrcu8,
  flea_bool_t            allow_wildcard__b,
  flea_bool_t*           result__pb
);


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