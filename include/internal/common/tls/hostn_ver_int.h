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

#ifndef _flea_hostn_ver_int__H_
# define _flea_hostn_ver_int__H_

# include "flea/byte_vec.h"
# include "flea/hostn_ver.h"

# ifdef __cplusplus
extern "C" {
# endif

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
  flea_bdec_t*             cont_dec__pt,
  flea_byte_vec_t*         work_spc__pt,
  flea_hostn_match_info_t* match_info__pt
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_x509__verify_host_name(
  const flea_ref_cu8_t*  user_host_name__pcrcu8,
  const flea_byte_vec_t* cert_dns_name__pcrcu8,
  flea_bool_t            allow_wildcard__b,
  flea_bool_t*           result__pb
) FLEA_ATTRIB_UNUSED_RESULT;


flea_err_e THR_flea_x509__vrfy_tls_srv_id(
  const flea_byte_vec_t*      user_id__pcrcu8,
  flea_host_id_type_e         host_type,
  const flea_x509_cert_ref_t* server_cert__pt
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_x509__vrfy_tls_srv_id_cstr(
  const char*                 user_id__cs,
  flea_host_id_type_e         host_type,
  const flea_x509_cert_ref_t* server_cert__pt
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
