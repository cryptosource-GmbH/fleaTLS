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

#ifndef _flea_test_pc__H_
#define _flea_test_pc__H_

#include "test_util.h"


#ifdef FLEA_HAVE_TLS_CLIENT
int flea_start_tls_client(property_set_t const& cmdl_args);
#endif

#ifdef FLEA_HAVE_TLS_SERVER
int flea_start_tls_server(property_set_t const& cmdl_args);
int flea_start_https_server(property_set_t const& cmdl_args);
#endif


flea_err_e THR_fleatest_iterate_cert_files_and_verify_as_self_signed(
  std::string const &dir_name,
  bool              expect_error,
  std::vector<unsigned char> = { }

);

flea_err_e THR_flea_test_test_dir_full_of_invalid_certs(std::string const& top_dir_name);

#ifdef FLEA_HAVE_TLS_CS_PSK

typedef struct
{
  flea_u8_t* identity__pu8;
  flea_u16_t identity_len__u16;
  flea_u8_t* psk__pu8;
  flea_u16_t psk_len__u16;
} flea_tls_psk_t;

#endif // ifdef FLEA_HAVE_TLS_CS_PSK

#endif /* h-guard */
