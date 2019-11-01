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

#ifndef _flea_tls_client_int__H_
#define _flea_tls_client_int__H_

#ifdef __cplusplus
extern "C" {
#endif


flea_err_e THR_flea_tls_ctx_t__client_handle_server_initiated_reneg(
  flea_tls_clt_ctx_t*                   tls_client_ctx__pt,
  const flea_hostn_validation_params_t* hostn_valid_params__pt
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
