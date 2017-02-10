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

#ifdef FLEA_HAVE_RSA

# define CHECK_NOT_NEGATIVE(__f) do {if(__f < 0) {return FLEA_ERR_INT_ERR;}} while(0)
# define CHECK_ZERO(__f)         do {if(__f != 0) {return FLEA_ERR_INT_ERR;}} while(0)
static flea_err_t THR_flea_test_crt_rsa_raw_file_based_for_file(std::string const& leaf_name)
{
  std::string file_name = "misc/testdata/" + leaf_name; // .dat";
  unsigned mod_byte_len = 2048 / 8;
  std::ifstream input(file_name.c_str());
  std::string line;
  bool end = false;
  try
  {
    while(!end)
    {
      std::vector<flea_u8_t> p          = parse_line("p", 0, input);
      std::vector<flea_u8_t> q          = parse_line("q", 0, input);
      std::vector<flea_u8_t> d1         = parse_line("d1", 0, input);
      std::vector<flea_u8_t> d2         = parse_line("d2", 0, input);
      std::vector<flea_u8_t> q_inv      = parse_line("q_inv", 0, input);
      std::vector<flea_u8_t> pub_exp    = parse_line("pub_exp", mod_byte_len, input);
      std::vector<flea_u8_t> priv_exp   = parse_line("priv_exp", mod_byte_len, input);
      std::vector<flea_u8_t> mod        = parse_line("mod", mod_byte_len, input);
      std::vector<flea_u8_t> message    = parse_line("message", mod_byte_len, input);
      std::vector<flea_u8_t> ciphertext = parse_line("signature", mod_byte_len, input);
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

      if(0 != THR_flea_test_rsa_crt_inner(
          mod_byte_len,
          &ciphertext[0],
          &message[0],
          &p[0],
          p.size(),
          &q[0],
          q.size(),
          &d1[0],
          d1.size(),
          &d2[0],
          d2.size(),
          &q_inv[0],
          q_inv.size(),
          // &pub_exp[0],
          &mod[0]
        ))
      {
        std::cout << "error in file " << leaf_name << ", test with mod = ";
        for(unsigned j = 0; j < mod.size(); j++)
        {
          std::printf("%02x", mod[j]);
        }
        std::cout << std::endl;
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
} // THR_flea_test_crt_rsa_raw_file_based_for_file

flea_err_t THR_flea_test_crt_rsa_raw_file_based()
{
  CHECK_ZERO(THR_flea_test_crt_rsa_raw_file_based_for_file(std::string("raw_crt_rsa_2048_previous_failure.dat")));
  CHECK_ZERO(THR_flea_test_crt_rsa_raw_file_based_for_file(std::string("raw_crt_rsa_2048_pq_max_32_bit_diff.dat")));
  CHECK_ZERO(THR_flea_test_crt_rsa_raw_file_based_for_file(std::string("raw_crt_rsa_2048_with_short_messages.dat"))); // also features d1,d2,q_inv one byte shorter than mod
  // rather redundant now:
  // CHECK_ZERO(THR_flea_test_crt_rsa_raw_file_based_for_file(std::string("raw_crt_rsa_2048.dat")));
  return FLEA_ERR_FINE;
}

#endif // ifdef FLEA_HAVE_RSA
