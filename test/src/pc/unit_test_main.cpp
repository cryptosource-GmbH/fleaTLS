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

#include <fcntl.h> // linux specific
#include <sys/stat.h> // linux specific
#include <unistd.h>
#include "flea_test/linux_util.h"
#include "internal/common/default.h"

int main(
  int          argc,
  const char** argv
)
{
  int res = 0;
  property_set_t cmdl_args(argc, argv);
  flea_u8_t rnd_seed__au8 [32] = {0};

  if(!cmdl_args.have_index("deterministic"))
  {
    /*
     * Read random bytes from the /dev/urandom. This is used for the test
     * implementation here. Note that for a productive implementation on a Unix
     * system the file /dev/random (or /dev/arandom under certain circumstances
     * and if it is available) should be used instead. An
     * alternative can be the getrandom() system call if available.
     */
    int rand_device        = open("/dev/urandom", O_RDONLY);
    ssize_t read_rnd_bytes = read(rand_device, rnd_seed__au8, sizeof(rnd_seed__au8));
    if(read_rnd_bytes != sizeof(rnd_seed__au8))
    {
      printf("error reading /dev/urandom\n");
      exit(1);
    }
    close(rand_device);
  }
  else
  {
    printf("flea test: running deterministic tests\n");
  }
  printf("rng seed = ");
  for(unsigned i = 0; i < sizeof(rnd_seed__au8); i++)
  {
    printf("%02x", rnd_seed__au8[i]);
  }
  printf("\n");

#ifdef FLEA_HAVE_MUTEX
  flea_mutex_func_set_t mutex_func_set__t = {
    .init   = flea_linux__pthread_mutex_init,
    .destr  = pthread_mutex_destroy,
    .lock   = pthread_mutex_lock,
    .unlock = pthread_mutex_unlock
  };

#endif // ifdef FLEA_HAVE_MUTEX
  if(THR_flea_lib__init(
      &THR_flea_linux__get_current_time,
      (const flea_u8_t*) &rnd_seed__au8,
      sizeof(rnd_seed__au8),
      NULL
#ifdef FLEA_HAVE_MUTEX
      ,
      &mutex_func_set__t
#endif
    ))
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
      " --psk_identity_hint=hint When this option is supplied to the server, it sends the supplied identity hint during the handshake and applies a specific test key derivation function to the PSK. Works with the fleaTLS command line client which, when it receives the identity hint, applies the same key derivation to the PSK, given that this command line option --enable_psk_identity_hint is set."
      "--enable_psk_identity_hint if this option is set for the TLS client, then it is able to handle an identity hint from a fleaTLS command line server.");
    std::cout << help << std::endl;
    return 0;
  }

  try
  {
    if(cmdl_args.have_index("tls_client"))
    {
#ifdef FLEA_HAVE_TLS_CLIENT
      res = flea_start_tls_client(cmdl_args);
      std::cout << "tls client stopping with error code = " << std::hex << res << std::dec
                << " ( exit code suppressed)\n";
      res = 0;
#else // ifdef FLEA_HAVE_TLS_CLIENT
      std::cerr << "TLS Client not configured" << std::endl;
      exit(1);
#endif // ifdef FLEA_HAVE_TLS_CLIENT
    }
    else if(cmdl_args.have_index("tls_server"))
    {
#ifdef FLEA_HAVE_TLS_SERVER
      res = flea_start_tls_server(cmdl_args);
      std::cout << "tls server stopping with error code = " << std::hex << res << std::dec
                << " ( exit code suppressed)\n";
      res = 0;
#else // ifdef FLEA_HAVE_TLS_SERVER
      std::cerr << "TLS Server not configured" << std::endl;
      exit(1);
#endif // ifdef FLEA_HAVE_TLS_SERVER
    }
    else if(cmdl_args.have_index("https_server"))
    {
#ifdef FLEA_HAVE_TLS_SERVER
      res = flea_start_https_server(cmdl_args);
      std::cout << "https server stopping with error code = " << std::hex << res << std::dec
                << " ( exit code suppressed)\n";
      res = 0;
#else // ifdef FLEA_HAVE_TLS_SERVER
      std::cerr << "TLS Server not configured" << std::endl;
      exit(1);
#endif // ifdef FLEA_HAVE_TLS_SERVER
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

      std::string file_path_to_be_replaced_by_std_in_str = cmdl_args.get_property_as_string_default_empty(
        "path_rpl_stdin"
        );
      const char* file_path_to_be_replaced_by_std_in = file_path_to_be_replaced_by_std_in_str.c_str();

      res = flea_unit_tests(reps, cert_path_prefix, file_path_to_be_replaced_by_std_in, func_prefix, full__b);
    }
  }
  catch(std::exception const& e)
  {
    std::cerr << "an execption occured during flea test execution: " << e.what() << std::endl;
  }
  flea_lib__deinit();

  return res;
} // main
