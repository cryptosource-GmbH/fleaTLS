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

#ifndef _flea_cert_verify_int__H_
# define _flea_cert_verify_int__H_

# include "internal/common/cert_info_int.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Verify that a certificate is signed by the public key of another
 * certificate. Does not perform certificate path validation, only the
 * signature verification itself.
 *
 */
flea_err_e THR_flea_x509_verify_cert_info_signature(
  const flea_x509_cert_info_t* subject_cert_ref__pt,
  const flea_x509_cert_info_t* issuer_cert_ref__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif

#endif /* h-guard */
