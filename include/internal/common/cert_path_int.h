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

#ifndef _flea_cert_path_int__H_
# define _flea_cert_path_int__H_

# include "flea/x509.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_ref_cu8_t data_ref__rcu8;
  flea_u8_t      trusted_flag;
} flea_enc_cert_ref_t;

/**
 * validate notBefore & notAfter and Basic Constraint (but not the pathlen)
 */
flea_err_e THR_flea_cert_path__validate_single_cert(
  flea_x509_cert_ref_t*  cert_ref__pt,
  flea_bool_t            is_trusted__b,
  flea_bool_t            is_target__b,
  const flea_gmt_time_t* arg_compare_time_mbn__pt
) FLEA_ATTRIB_UNUSED_RESULT;
# ifdef __cplusplus
}
# endif

#endif /* h-guard */
