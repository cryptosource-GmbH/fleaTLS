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

  if(cmdl_args.have_index("random"))
  {
    printf("flea test: running randomized tests\n");
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rnd = (tv.tv_sec * tv.tv_usec) ^ tv.tv_sec ^ tv.tv_usec;
    printf("rnd = %u\n", rnd);
  }

  if(THR_flea_lib__init() || THR_flea_rng__reseed_volatile((flea_u8_t *) &rnd, sizeof(rnd)))
  {
    FLEA_PRINTF_1_SWITCHED("error with lib init, tests aborted\n");
    return 1;
  }
  if(cmdl_args.have_index("tls_client"))
  {
    res = flea_start_tls_client(cmdl_args);
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
  flea_lib__deinit();

  return res;
} // main
