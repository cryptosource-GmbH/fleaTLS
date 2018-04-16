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

static properties_spec_t create_properties_spec()
{
  properties_spec_t result;

  std::string cl("TLS client");
  std::string se("TLS server");
  std::string un("unit tests");
  std::string tls("TLS client and server");
  std::string fz("Fuzzing with AFL");
  std::string ge("General");
  result["help"]       = properties_spec_entry_t("print this help text").set_group(ge);
  result["tls_client"] = properties_spec_entry_t("instantiate a fleaTLS client", "").set_group(cl);
  result["tls_server"] = properties_spec_entry_t("instantiate a fleaTLS server", "").set_group(se);
  result["trusted"]    = properties_spec_entry_t(
    "Comma seperated list of file paths of DER encoded certificates which are trusted for the purpose of validating the peer. This argument is optional for the server - if it is provided, then client authentication is required.",
    "certs"
    ).set_group(tls);
  result["own_certs"] = properties_spec_entry_t(
    "A single file path to the peer's own DER encoded EE certificate. This argument is optional for the client.",
    "certs"
    ).set_group(tls);
  result["own_ca_chain"] = properties_spec_entry_t(
    "comma seperated list of file paths of DER encoded certificates that form the chain of certificates beyond the own EE (which must not be part of this list) to be send to the peer during the handshake The order must be starting from the issuer of the EE ending at the root certificate which is trusted by the peer.",
    "certs"
    ).set_group(tls);
  result["own_private_key"] = properties_spec_entry_t(
    "file path to the PKCS#8 binary file containing this instance's private key. Must be the private key corresponding to the 'own_cert'.",
    "private_key_file"
    ).set_group(tls);
  result["crls"] = properties_spec_entry_t(
    "Comma seperated list of CRL files (DER encoded) to be used by the TLS client or server for revocation checking.",
    "crl-list"
    ).set_group(tls);
  result["port"] = properties_spec_entry_t(
    "The number of the port at which to open the connection / connect to the server",
    "port",
    "4444"
    ).set_group(tls);
  result["hostname"] = properties_spec_entry_t("hostname of the server", "hostname").set_group(cl);
  result["ip_addr"]  = properties_spec_entry_t(
    "IP address of the server Either this or --hostname must be provided",
    "address"
    ).set_group(cl);
  result["no_hostn_ver"] = properties_spec_entry_t(
    "Optional - suppresses the hostname verification",
    ""
    ).set_group(cl);
  result["psk"] = properties_spec_entry_t(
    "The PSK secret to be used with TLS. If specified for the client, the use of a PSK cipher suite will be enforced. For the server, PSK will be available additionally to certificate based cipher suites.",
    "psk-value"
    ).set_group(tls);
  result["psk_identity"] = properties_spec_entry_t(
    "The PSK identity. The TLS client will send this identity during the handshake. The TLS server will expect this and only this PSK identity",
    "identity"
    ).set_group(tls);
  result["psk_identity_hint"] = properties_spec_entry_t(
    "When this option is supplied to the server, it sends the supplied identity hint during the handshake and applies a specific test key derivation function to the PSK. Works with the fleaTLS command line client which, when it receives the identity hint, applies the same key derivation to the PSK, given that this command line option --enable_psk_identity_hint is set.",
    "hint"
    ).set_group(se);
  result["enable_psk_identity_hint"] = properties_spec_entry_t(
    "If this option is set for the TLS client, then it is able to handle an identity hint from a fleaTLS command line server.",
    ""
    ).set_group(tls);
  result["stay"] = properties_spec_entry_t(
    "cause the TLS client or server to hold the established connection after the initial handhsake. Otherwise it will be terminated after the initial handshake",
    ""
    ).set_group(tls);
  result["allowed_sig_algs"] = properties_spec_entry_t(
    "Comma separated list of allowed signature algorithms for the TLS client or server. Allowed values are " + get_comma_seperated_list_of_supported_sig_algs() + ". If this property is not specified, then all signature algorithms according to the build configuration are supported",
    "list-of-sig-algs"
    ).set_group(tls);
  result["cipher_suites"] = properties_spec_entry_t(
    "Comma seperated list of ciphersuites that are allowed. Supported cipher suites are " + get_comma_seperated_list_of_allowed_values(
      cipher_suite_name_value_map__t
    ) + ". If this property is not specified, all cipher suites configured in the build configuration will be supported.",
    "list-of-cipher-suites"
    ).set_group(tls);
  result["allowed_curves"] = properties_spec_entry_t(
    "Comma separated list of allowed elliptic curve domain parameters to be used by the TLS client and server during the handshake. Allowed values are " + get_comma_seperated_list_of_allowed_values(
      curve_id_name_value_map__t
    ) + ". If this parameter is not specified, then all algorithms activated in the build configuration will be supported.",
    "curve-list"
    ).set_group(tls);


  result["reneg_mode"] = properties_spec_entry_t(
    "Specification how the TLS client or server handles renegotiations. allowed values are: 'no_reneg', 'only_secure_reneg', and 'allow_insecure_reneg'",
    "reneg_mode",
    "only_secure_reneg"
    ).set_group(tls);
  result["app_data_read_mode"] = properties_spec_entry_t(
    "Spefication of the read-blocking behaviour of a TLS client or server when reading application data. Possible values are: 'full', 'blocking', and 'non-blocking'",
    "read_mode",
    "nonblocking"
    ).set_group(tls);
  result["app_data_read_size"] = properties_spec_entry_t(
    "the attempted read size when reading application data",
    "read_size",
    "20000"
    ).set_group(tls);
  result["rev_chk"] = properties_spec_entry_t(
    "the revocation checking mode. Possible values are 'all', 'none', and 'only_ee'. In case of 'all', the revocation check is applied to the whole certificate chain",
    "rev_chck_mode",
    "none"
    ).set_group(tls);
  result["stream_input_file_dir"] = properties_spec_entry_t(
    "For using AFL on fleaTLS: Directory from which files are read providing the peers TLS handshake messages as a replacement to the network connection.",
    "dir"
    ).set_group(fz);
  result["path_rpl_stdin"] = properties_spec_entry_t(
    "For using AFL on fleaTLS: The path to one of the files read from stream_input_file_dir, which is replaced by the input read from the standard in file descriptor",
    "path"
    ).set_group(fz);
  result["read_timeout"] = properties_spec_entry_t(
    "Read timeout in milliseconds applied to the network connection. The value '0' indicates that no timeout should be used.",
    "timeout(ms)",
    "1000"
    ).set_group(tls);
  result["do_renegs"] = properties_spec_entry_t(
    "Specify the number of renegotiations that the TLS client or server will try to carry out directly after a successful handshake.",
    "nb-renegs",
    "0"
    ).set_group(tls);
  result["session"] = properties_spec_entry_t(
    "A stored session to be resumed in the handshake encoded in hex.",
    "stored_session_hex"
    ).set_group(cl);
  result["session_in"] = properties_spec_entry_t(
    "A file containing a stored session to be resumed in the handshake encoded in binary that was previously written with --session_out.",
    "session-file"
    ).set_group(cl);
  result["session_out"] = properties_spec_entry_t(
    "A file to be created and receive the session for later resumption.",
    "session-file"
    ).set_group(cl);
  result["threads"] = properties_spec_entry_t(
    "The maximum number of parallel threads for handling client connections that the server will run at a time",
    "nb-of-threads",
    "1"
    ).set_group(se);
  result["no_session_manager"] = properties_spec_entry_t(
    "Disables the use of the session manager and thus session resumption."
    ).set_group(se);
  result["session_validity_seconds"] = properties_spec_entry_t(
    "Specifies the number of seconds for which a session that was stored in the server's session manager is available for resumption.",
    "seconds",
    "3600"
    ).set_group(se);
  result["deterministic"] = properties_spec_entry_t(
    "the tool starts with a predefined state of fleaTLS's RNG in order to allow for repoducible test results"
    ).set_group(ge);
  result["cert_path_prefix"] = properties_spec_entry_t(
    "Prefix of a test name (=directory name) for the certificate path tests. Only tests with names matching this prefix will be executed",
    "prefix"
    ).set_group(un);
  result["func_prefix"] = properties_spec_entry_t(
    "Prefix for the test function names of tests to be executed. Only test function with names beginning with this value will be executed",
    "prefix"
    ).set_group(un);
  result["repeat"] = properties_spec_entry_t(
    "Number of repetitions for the execution of the unit test suite",
    "iterations",
    "1"
    );
  result["full"] = properties_spec_entry_t("Execute additional extensive tests").set_group(un);


  return result;
} // create_properties_spec

int main(
  int          argc,
  const char** argv
)
{
  int res = 0;
  property_set_t cmdl_args(argc, argv, create_properties_spec());
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
      "usage 1 - unit tests: \"./build/unit_test\" \n" // unit test specific parameters still missing
      "usage 2 - tls client: \"./build/unit_test --tls_client ... \"  \n"
      "usage 3 - tls server: \"./build/unit_test --tls_server ... \"  \n"
      "\n"
      "parameters:\n "
      + cmdl_args.get_help_str());
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

      reps = cmdl_args.get_property_as_u32("repeat");
      bool full = cmdl_args.have_index("full");
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
