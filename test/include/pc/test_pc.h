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


flea_err_t THR_fleatest_iterate_cert_files_and_verify_as_self_signed(
  std::string const &dir_name,
  bool              expect_error,
  std::vector<unsigned char> = { }

);

flea_err_t THR_flea_test_test_dir_full_of_invalid_certs(std::string const& top_dir_name);

#endif /* h-guard */
