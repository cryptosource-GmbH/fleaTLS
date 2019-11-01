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


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/cert_verify.h"
#include "internal/common/ber_dec.h"
#include "test_data_x509_certs.h"
#include "self_test.h"

#include <string.h>

#ifdef FLEA_HAVE_ASYM_SIG

# ifdef FLEA_HAVE_RSA
flea_err_e THR_flea_test_cert_verify_rsa()
{
  FLEA_THR_BEG_FUNC();
#  if FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096
  FLEA_CCALL(
    THR_flea_x509_verify_cert_signature(
      test_cert_tls_server_1,
      sizeof(test_cert_tls_server_1),
      flea_test_cert_issuer_of_tls_server_1__cau8,
      sizeof(flea_test_cert_issuer_of_tls_server_1__cau8),
      flea_x509_validation_empty_flags
    )
  );
#  endif /* if FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096 */
  FLEA_THR_FIN_SEC_empty();
}

# endif /* ifdef FLEA_HAVE_RSA */

# ifdef FLEA_HAVE_ECDSA
flea_err_e THR_flea_test_cert_verify_ecdsa()
{
  FLEA_THR_BEG_FUNC();
#  if FLEA_ECC_MAX_MOD_BIT_SIZE >= 384 && defined FLEA_HAVE_SHA384_512
  FLEA_CCALL(
    THR_flea_x509_verify_cert_signature(
      test_self_signed_ecdsa_csca_cert__acu8,
      sizeof(test_self_signed_ecdsa_csca_cert__acu8),
      test_self_signed_ecdsa_csca_cert__acu8,
      sizeof(test_self_signed_ecdsa_csca_cert__acu8),
      flea_x509_validation_empty_flags
    )
  );
#  endif /* if FLEA_ECC_MAX_MOD_BIT_SIZE >= 384 */
  FLEA_THR_FIN_SEC_empty();
}

# endif /* ifdef FLEA_HAVE_ECDSA */


#endif /* #ifdef FLEA_HAVE_ASYM_SIG */
