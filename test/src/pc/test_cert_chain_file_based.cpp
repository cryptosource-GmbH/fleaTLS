/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */



#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <exception>
#include "pc/test_util.h"
#include "flea/error_handling.h"
#include "flea/cert_chain.h"

using namespace std;


// TODO: EVALUATE KEY LEN REQ IN TESTS
#if defined FLEA_HAVE_RSA && ( FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
static flea_err_t THR_flea_execute_path_test_case_for_properties(std::string const& dir_path, property_set_t const& prop)
{

  FLEA_THR_BEG_FUNC();
  std::vector<std::string> trust_anchor_files = get_entries_of_dir(dir_path + "/trust_anchors", dir_entries_with_path);
  std::vector<std::string> cert_files = get_entries_of_dir(dir_path + "/certs", dir_entries_with_path);
  std::vector<std::string> target_cert_files = get_entries_of_dir(dir_path + "/target_cert", dir_entries_with_path);
  //property_set_t prop(dir_path + "/test.ini"); 
  FLEA_PRINTF_2_SWITCHED("using ini file %s\n", prop.get_filename().c_str());
  if(target_cert_files.size() != 1)
  {
    throw test_utils_exceptn_t("invalid number of target certificates in test case " + dir_path);
  }
  vector<vector<flea_u8_t>> anchors;
  vector<vector<flea_u8_t>> certs;
  std::vector<flea_u8_t*> anchor_ptrs;
  std::vector<flea_u8_t*> cert_ptrs;
  std::vector<flea_u32_t> anchor_lens;
  std::vector<flea_u32_t> cert_lens;
  // the others may well be empty
  vector<unsigned char> target_cert = read_bin_file(target_cert_files[0]);
  flea_err_t err;
  for(string anchor_file: trust_anchor_files)
  {
    vector<unsigned char> cert = read_bin_file(anchor_file);
    anchors.push_back(cert);
    anchor_ptrs.push_back(&anchors[anchors.size() - 1][0]);
    anchor_lens.push_back(anchors[anchors.size() - 1].size());
  }
  for(string cert_file: cert_files)
  {
    vector<unsigned char> cert = read_bin_file(cert_file);
    certs.push_back(cert);
    cert_ptrs.push_back(&certs[certs.size() - 1][0]);
    cert_lens.push_back(certs[certs.size() - 1].size());
  }
  string time_str = prop.get_property_as_string("date");
  err = THR_flea_test_cert_path_generic(
      &target_cert[0], target_cert.size(),
      &anchor_ptrs[0], &anchor_lens[0], anchor_ptrs.size(),
      &cert_ptrs[0], &cert_lens[0], cert_ptrs.size(),
      (const flea_u8_t*)time_str.c_str(), time_str.size()
      ); 
  bool valid = prop.get_as_bool_default_true("valid");
  if(valid && err)
  {
    //std::cout << "expected vali
    /* the validation may have failed because we are testing with too small
     * MAX_CERT_CHAIN_DEPTH 
     */
    if(!(prop.get_property_as_u32_default("required_chainlen", 10) > FLEA_MAX_CERT_CHAIN_DEPTH))
    {
      std::cout << "test '" << prop.get_filename() << "': unsuccessful verification of correct cert chain, error code = " << std::hex << err << std::dec << std::endl;
      FLEA_THROW("unsuccessful validation of valid cert path", FLEA_ERR_FAILED_TEST);
    }
    else
    {
      //std::cout << "ignoring failure of test "  << prop.get_filename() << " because of chain len restriction" << std::endl;
    }
  }
  else if(!valid && !err)
  {
      std::cout << "test '" << prop.get_filename() << "': unexpexted successful chain verification" << std::endl;
    FLEA_THROW("successful validation of invalid cert path", FLEA_ERR_FAILED_TEST);
  }


  /*FLEA_CCALL(THR_flea_cert_chain_t__add_cert_without_trust_status(&cert_chain__t, &subject));
    err = THR_flea_cert_chain__build_and_verify_cert_chain(&cert_chain__t);*/

  FLEA_THR_FIN_SEC_empty(
      //   flea_cert_chain_t__dtor(&cert_chain__t); 
      );
}

static flea_err_t THR_flea_execute_path_test_case(std::string const& dir_path)
{
  FLEA_THR_BEG_FUNC();
  vector<string> prop_files = get_entries_of_dir(dir_path, dir_entries_with_path, ".ini");
  for(string const& prop_file: prop_files)
  {
    //std::cout << "using property file " << prop_file << std::endl;
    property_set_t prop(prop_file);
    FLEA_CCALL(THR_flea_execute_path_test_case_for_properties(dir_path, prop));
  }
  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_test_path_validation_file_based(const char* cert_path_prefix )
{
  FLEA_THR_BEG_FUNC();
  std::string path_test_main_dir = "misc/testdata/cert_paths/";
  std::vector<std::string> test_cases;
  flea_u32_t nb_test_execution_repetitions_due_randomized_cert_order = 5;
  if(cert_path_prefix != nullptr)
  {
    nb_test_execution_repetitions_due_randomized_cert_order = 1;
    test_cases = get_entries_of_dir(path_test_main_dir, dir_entries_with_path, "" /*postfix*/, cert_path_prefix);
  }
  else
  {
    test_cases = get_entries_of_dir(path_test_main_dir, dir_entries_with_path);
  }
  flea_u32_t err_count = 0;
  for(string test: test_cases)
  {
    //const flea_u32_t nb_test_execution_repetitions_due_randomized_cert_order = 20;
    for(flea_u32_t i = 0; i < nb_test_execution_repetitions_due_randomized_cert_order; i++)
    {
      if(THR_flea_execute_path_test_case(test))
      {
        err_count++;
        break;
      }
    }
  }
  if(err_count)
  {
    FLEA_THROW("there were failed path tests", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}
#endif /* #if defined FLEA_HAVE_RSA && (defined FLEA_USE_HEAP_BUF || FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */
