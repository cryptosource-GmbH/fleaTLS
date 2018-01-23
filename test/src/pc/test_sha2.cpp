/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/types.h"
#include "self_test.h"
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include "pc/test_util.h"

static flea_err_e THR_flea_test_hash_file_based_inner(
  std::string const& leaf_name,
  flea_hash_id_e   hash_id
)
{
  // std::string leaf_name = "sha256_test.dat";
  std::string file_name = "misc/testdata/" + leaf_name;


  std::ifstream input(file_name.c_str());


  bool end = false;
  try
  {
    while(!end)
    {
      std::vector<flea_u8_t> m = parse_hex_prop_line("m", 0, input);
      std::vector<flea_u8_t> d = parse_hex_prop_line("d", 0, input);

      std::string line;
      if(!getline(input, line))
      {
        std::cout << "file error" << std::endl;
        return FLEA_ERR_INT_ERR;
      }
      if(line.find(std::string("next")) == 0)
      {
        // std::cout << "next test: " << line << std::endl;
        // nothing to do
      }
      else if(line.find(std::string("end")) == 0)
      {
        end = true;
      }
      // std::cout << "testing hash with message size = " << m.size() << std::endl;
      if(0 != THR_flea_test_hash_function_inner(
          &m[0],
          m.size(),
          &d[0],
          d.size(),
          hash_id
        ))
      {
        return FLEA_ERR_FAILED_TEST;
      }
    } // end while loop
  }
  catch(std::exception & e)
  {
    std::cout << "error during the parsing of test data" << e.what() << std::endl;
    throw(e);
  }
  return FLEA_ERR_FINE;
} // THR_flea_test_sha256_file_based

flea_err_e THR_flea_test_hash_file_based()
{
  FLEA_THR_BEG_FUNC();

#ifdef FLEA_HAVE_MD5
  FLEA_CCALL(THR_flea_test_hash_file_based_inner(std::string("md5_test.dat"), flea_md5));
#endif
  FLEA_CCALL(THR_flea_test_hash_file_based_inner(std::string("sha224_test.dat"), flea_sha224));
  FLEA_CCALL(THR_flea_test_hash_file_based_inner(std::string("sha256_test.dat"), flea_sha256));
#ifdef FLEA_HAVE_SHA1
  FLEA_CCALL(THR_flea_test_hash_file_based_inner(std::string("sha1_test.dat"), flea_sha1));
#endif
#ifdef FLEA_HAVE_SHA384_512
  FLEA_CCALL(THR_flea_test_hash_file_based_inner(std::string("sha384_test.dat"), flea_sha384));
  FLEA_CCALL(THR_flea_test_hash_file_based_inner(std::string("sha512_test.dat"), flea_sha512));
#endif
  FLEA_THR_FIN_SEC_empty();
}
