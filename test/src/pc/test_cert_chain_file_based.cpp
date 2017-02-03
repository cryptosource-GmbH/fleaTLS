/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <exception>
#include "pc/test_util.h"
#include "flea/error_handling.h"
#include "flea/cert_path.h"

using namespace std;


// TODO: EVALUATE KEY LEN REQ IN TESTS
#if defined FLEA_HAVE_RSA && ( FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
static flea_err_t THR_flea_execute_path_test_case_for_properties(std::string const& dir_path, property_set_t const& prop)
{
  FLEA_THR_BEG_FUNC();
  std::vector<std::string> trust_anchor_files = get_entries_of_dir(dir_path + "/trust_anchors", dir_entries_with_path);
  std::vector<std::string> cert_files         = get_entries_of_dir(dir_path + "/certs", dir_entries_with_path);
  std::vector<std::string> target_cert_files  = get_entries_of_dir(dir_path + "/target_cert", dir_entries_with_path);
  flea_bool_t disable_revocation_checking     = (false == is_dir_existent(dir_path + "/crls")) ? FLEA_TRUE : FLEA_FALSE;
  std::vector<std::string> crl_files;
  if(!disable_revocation_checking)
  {
    crl_files = get_entries_of_dir(dir_path + "/crls", dir_entries_with_path);
  }

  // property_set_t prop(dir_path + "/test.ini");
  FLEA_PRINTF_2_SWITCHED("using ini file %s\n", prop.get_filename().c_str());
  if(target_cert_files.size() != 1)
  {
    throw test_utils_exceptn_t("invalid number of target certificates in test case " + dir_path);
  }
  vector<vector<flea_u8_t> > anchors;
  vector<vector<flea_u8_t> > certs;
  vector<vector<flea_u8_t> > crls;
  std::vector<flea_u8_t *> anchor_ptrs;
  std::vector<flea_u8_t *> cert_ptrs;
  std::vector<flea_u8_t *> crl_ptrs;
  std::vector<flea_u32_t> anchor_lens;
  std::vector<flea_u32_t> cert_lens;
  std::vector<flea_u32_t> crl_lens;
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
  for(string crl_file: crl_files)
  {
    vector<unsigned char> crl = read_bin_file(crl_file);
    crls.push_back(crl);
    crl_ptrs.push_back(&crls[crls.size() - 1][0]);
    crl_lens.push_back(crls[crls.size() - 1].size());
  }
  string time_str = prop.get_property_as_string("date");

  string host_id_str = prop.get_property_as_string_default_empty("host_id");
  flea_host_id_type_e host_id_type = flea_host_dnsname; /* will be overridden */
  flea_ref_cu8_t host_id__rcu8;
  flea_ref_cu8_t *host_id_mbn__prcu8 = nullptr;
  if(host_id_str != "")
  {
    string host_id_type_str = prop.get_property_as_string("host_id_type");
    if(host_id_type_str == "ip_addr")
    {
      // host_id_type = flea_host_ipaddr;
      throw test_utils_exceptn_t("host_id_type 'ip_addr' not yet supported");
    }
    else
    if(host_id_type_str == "dns_name")
    {
      host_id_type = flea_host_dnsname;
    }
    else
    {
      throw test_utils_exceptn_t(std::string("host_id_type '" + host_id_type_str + "' not supported"));
    }
    host_id__rcu8.data__pcu8 = reinterpret_cast<const flea_u8_t *>(host_id_str.c_str());
    host_id__rcu8.len__dtl   = std::strlen(host_id_str.c_str());
    host_id_mbn__prcu8       = &host_id__rcu8;
  }

  err = THR_flea_test_cert_path_generic(
    &target_cert[0], target_cert.size(),
    &anchor_ptrs[0], &anchor_lens[0], anchor_ptrs.size(),
    &cert_ptrs[0], &cert_lens[0], cert_ptrs.size(),
    &crl_ptrs[0], &crl_lens[0], crl_ptrs.size(),
    (const flea_u8_t *) time_str.c_str(), time_str.size(),
    disable_revocation_checking,
    host_id_mbn__prcu8,
    host_id_type
    );
  bool valid = prop.get_as_bool_default_true("valid");
  if(valid && err)
  {
    // std::cout << "expected vali

    /* the validation may have failed because we are testing with too small
     * MAX_CERT_CHAIN_DEPTH
     */
    if(!(prop.get_property_as_u32_default("required_chainlen", 10) > FLEA_MAX_CERT_CHAIN_DEPTH))
    {
      if(!prop.get_as_bool_default_false("suppress_validation_error"))
      {
        std::cout << "test '" << prop.get_filename() << "': unsuccessful verification of correct cert chain, error code = " << std::hex << err << std::dec << std::endl;
        FLEA_THROW("unsuccessful validation of valid cert path", FLEA_ERR_FAILED_TEST);
      }
    }
    else
    {
      // std::cout << "ignoring failure of test "  << prop.get_filename() << " because of chain len restriction" << std::endl;
    }
  }
  else
  if(!valid && !err)
  {
    std::cout << "test '" << prop.get_filename() << "': unexpexted successful chain verification" << std::endl;
    FLEA_THROW("successful validation of invalid cert path", FLEA_ERR_FAILED_TEST);
  }


  /*FLEA_CCALL(THR_flea_cert_chain_t__add_cert_without_trust_status(&cert_chain__t, &subject));
   * err = THR_flea_cert_chain__build_and_verify_cert_chain(&cert_chain__t);*/

  FLEA_THR_FIN_SEC_empty(
    //   flea_cert_chain_t__dtor(&cert_chain__t);
  );
} // THR_flea_execute_path_test_case_for_properties

static properties_spec_t create_cert_path_ini_file_spec()
{
  properties_spec_t spec;

  spec.insert(std::make_pair("date", ""));
  spec.insert(std::make_pair("valid", ""));
  spec.insert(std::make_pair("required_chainlen", ""));
  spec.insert(std::make_pair("host_id", ""));
  spec.insert(std::make_pair("host_id_type", ""));
  spec.insert(std::make_pair("required_chainlen", ""));
  spec.insert(std::make_pair("reason", ""));
  spec.insert(std::make_pair("required_rsa_key_len", ""));
  spec.insert(std::make_pair("suppress_validation_error", ""));

  return spec;
}

static flea_err_t THR_flea_execute_path_test_case(std::string const& dir_path)
{
  FLEA_THR_BEG_FUNC();
  properties_spec_t spec    = create_cert_path_ini_file_spec();
  vector<string> prop_files = get_entries_of_dir(dir_path, dir_entries_with_path, ".ini");
  for(string const& prop_file: prop_files)
  {
    // std::cout << "using property file " << prop_file << std::endl;
    property_set_t prop(prop_file, spec);
    FLEA_CCALL(THR_flea_execute_path_test_case_for_properties(dir_path, prop));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_path_validation_file_based(const char *cert_path_prefix, flea_u32_t *nb_exec_tests_pu32)
{
  FLEA_THR_BEG_FUNC();
  std::string path_test_main_dir = "misc/testdata/cert_paths/";
  std::vector<std::string> test_cases;
  flea_u32_t nb_test_execution_repetitions_due_randomized_cert_order = 5;
  if(cert_path_prefix != nullptr)
  {
    nb_test_execution_repetitions_due_randomized_cert_order = 1;
    test_cases = get_entries_of_dir(path_test_main_dir, dir_entries_with_path, "" /*postfix*/, cert_path_prefix);
    if(test_cases.size() == 0)
    {
      throw test_utils_exceptn_t("no matching cert path test for the specified prefix");
    }
  }
  else
  {
    test_cases = get_entries_of_dir(path_test_main_dir, dir_entries_with_path);
  }
  *nb_exec_tests_pu32 = test_cases.size();
  flea_u32_t err_count = 0;
  for(string test: test_cases)
  {
    // const flea_u32_t nb_test_execution_repetitions_due_randomized_cert_order = 20;
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
} // THR_flea_test_path_validation_file_based

#endif // if defined FLEA_HAVE_RSA && ( FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
