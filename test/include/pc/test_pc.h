#ifndef _flea_test_pc__H_
#define _flea_test_pc__H_

#include "test_util.h"


int flea_start_tls_client(property_set_t const& cmdl_args);
int flea_start_tls_server(property_set_t const& cmdl_args);

int flea_start_https_server(property_set_t const& cmdl_args);

flea_err_t THR_fleatest_iterate_cert_files_and_verify_as_self_signed(
  std::string const &dir_name,
  bool              expect_error
);

#endif /* h-guard */
