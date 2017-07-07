/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "self_test.h"
#include <stdio.h>
#include <iostream>
#include "pc/test_util.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h> // Linux specific
#include <exception>
#include <iostream>

#include "pc/test_pc.h"
#include "flea/lib.h"
#include "flea/rng.h"

int main(
  int          argc,
  const char** argv
)
{
  int res;
  flea_u32_t rnd = 0;
  property_set_t cmdl_args(argc, argv);

  if(!cmdl_args.have_index("deterministic"))
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rnd = (tv.tv_sec * tv.tv_usec) ^ tv.tv_sec ^ tv.tv_usec;
    printf("rnd = %u\n", rnd);
    printf("\n");
  }
  else
  {
    printf("flea test: running deterministic tests\n");
  }

  if(THR_flea_lib__init() || THR_flea_rng__reseed_volatile((flea_u8_t*) &rnd, sizeof(rnd)))
  {
    FLEA_PRINTF_1_SWITCHED("error with lib init, tests aborted\n");
    return 1;
  }

  if(cmdl_args.have_index("help"))
  {
    std::string help(
      "usage 1 - unit tests: ./build/unit_test: execute unit tests\n"
      "usage 2 - tls client: ./build/unit_test --tls_client ...   \n"
      "usage 3 - tls server: ./build/unit_test --tls_server ...   \n"
      "\n"
      "usage 2 & 3 support the following further arguments:\n\n"
      " --trusted=<comma seperated list of file paths of DER encoded certificates which are trusted for the purpose of validating the peer.> This argument is optional for the server.\n\n"
      " --own_certs=<a single file path to the peer's own DER encoded EE certificate> This argument is optional for the client.\n"
      " --own_ca_chain=<comma seperated list of file paths of DER encoded certificates that form the chain of certificates beyond the own EE (which must not be part of this list) to be send to the peer during the handshake> The order must be starting from the issuer of the EE ending at the root certificate which is trusted by the peer.\n\n"
      " --own_private_key=<file path to the PKCS#8 binary file containing this instance's private key> Must be the private key corresponding to the 'own_cert'.\n\n"
      " --port=<port nr.> The number of the port at which to open the connection / connect to the server\n\n"
      "\n\n"
      "for the tls client the following further arguments are supported:\n\n"
      " --hostname=<hostname of the server>\n\n"
      " --ip_addr=<IP address of the server> Either this or --hostname must be provided\n\n"
      " --no_hostn_ver Optional - suppresses the hostname verification\n\n"
    );
    std::cout << help << std::endl;
    return 0;
  }
  ;
  try
  {
    if(cmdl_args.have_index("tls_client"))
    {
#ifdef FLEA_HAVE_TLS
      res = flea_start_tls_client(cmdl_args);
#else
      std::cerr << "TLS not configured" << std::endl;
      exit(1);
#endif
    }
    else if(cmdl_args.have_index("tls_server"))
    {
#ifdef FLEA_HAVE_TLS
      res = flea_start_tls_server(cmdl_args);
#else
      std::cerr << "TLS not configured" << std::endl;
      exit(1);
#endif
    }
    else if(cmdl_args.have_index("https_server"))
    {
#ifdef FLEA_HAVE_TLS
      res = flea_start_https_server(cmdl_args);
#else
      std::cerr << "TLS not configured" << std::endl;
      exit(1);
#endif
    }
    else
    {
      flea_u32_t reps = 1;
      const char* cert_path_prefix = NULL;
      std::string cert_path_prefix_str;
      const char* func_prefix = NULL;
      std::string func_prefix_str;
      if(cmdl_args.have_index("cert_path_prefix"))
      {
        cert_path_prefix_str = cmdl_args.get_property_as_string("cert_path_prefix");
        cert_path_prefix     = cert_path_prefix_str.c_str();
      }
      if(cmdl_args.have_index("func_prefix"))
      {
        func_prefix_str = cmdl_args.get_property_as_string("func_prefix");
        func_prefix     = func_prefix_str.c_str();
      }

      reps = cmdl_args.get_property_as_u32_default("repeat", 1);
      bool full = cmdl_args.get_as_bool_default_false("full");
      flea_bool_t full__b = full ? FLEA_TRUE : FLEA_FALSE;


      res = flea_unit_tests(reps, cert_path_prefix, func_prefix, full__b);
    }
  }
  catch(std::exception const& e)
  {
    std::cerr << "an execption occured during flea test execution: " << e.what() << std::endl;
  }
  flea_lib__deinit();

  return res;
} // main
