/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

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
