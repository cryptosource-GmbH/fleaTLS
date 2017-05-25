/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/tls.h"
#include "pc/test_pc.h"
#include "pc/test_util.h"

using namespace std;

#ifdef FLEA_HAVE_TLS

/*
 * struct cipher_suite_name_and_value_t
 * {
 * std::string name;
 * flea_u16_t  value;
 * } ;*/

std::map<string, flea_u16_t> cipher_suite_name_value_map__t = {
  {"TLS_RSA_WITH_NULL_MD5",           0x0001},
  {"TLS_RSA_WITH_NULL_SHA",           0x0002},
  {"TLS_RSA_WITH_NULL_SHA256",        0x003B},
  {"TLS_RSA_WITH_RC4_128_MD5",        0x0004},
  {"TLS_RSA_WITH_RC4_128_SHA",        0x0005},
  {"TLS_RSA_WITH_3DES_EDE_CBC_SHA",   0x000A},
  {"TLS_RSA_WITH_AES_128_CBC_SHA",    0x002F},
  {"TLS_RSA_WITH_AES_256_CBC_SHA",    0x0035},
  {"TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003C},
  {"TLS_RSA_WITH_AES_256_CBC_SHA256", 0x003D},
  {"TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009C},
  {"TLS_RSA_WITH_AES_256_GCM_SHA384", 0x009D}
};

namespace {
std::vector<flea_u16_t> get_cipher_suites_from_cmdl(property_set_t const& cmdl_args)
{
  std::vector<flea_u16_t> result;
  if(cmdl_args.have_index("cipher_suites"))
  {
    std::vector<string> strings = tokenize_string(cmdl_args.get_property_as_string("cipher_suites"), ',');
    for(string s : strings)
    {
      const flea_tls__cipher_suite_t* ptr;
      auto it = cipher_suite_name_value_map__t.find(s);
      if(it == cipher_suite_name_value_map__t.end() ||
        THR_flea_tls_get_cipher_suite_by_id(static_cast<flea_tls__cipher_suite_id_t>(it->second), &ptr))
      {
        throw test_utils_exceptn_t("specified cipher suite '" + s + "' not configured");
      }
      result.push_back(cipher_suite_name_value_map__t[s]);
    }
  }
  else
  {
    for(auto & entry : cipher_suite_name_value_map__t)
    {
      flea_u16_t id = entry.second;
      const flea_tls__cipher_suite_t* ptr;
      if(!THR_flea_tls_get_cipher_suite_by_id(static_cast<flea_tls__cipher_suite_id_t>(id), &ptr))
      {
        result.push_back(id);
      }
    }
  }
  if(result.size() == 0)
  {
    throw test_utils_exceptn_t("no cipher_suite specified");
  }
  return result;
} // get_cipher_suites_from_cmdl
}
flea_err_t THR_flea_tls_tool_set_tls_cfg(
  flea_cert_store_t*  trust_store__pt,
  flea_ref_cu8_t*     cert_chain,
  flea_al_u16_t*      cert_chain_len,
  flea_ref_cu8_t*     server_key,
  property_set_t const& cmdl_args,
  tls_test_cfg_t      & cfg
)
{
  cfg.trusted_certs  = cmdl_args.get_bin_file_list_property("trusted");
  cfg.server_key_vec = cmdl_args.get_bin_file("own_private_key");
  cfg.own_certs      = cmdl_args.get_bin_file_list_property("own_certs");
  cfg.own_ca_chain   = cmdl_args.get_bin_file_list_property("own_ca_chain");
  cfg.cipher_suites  = get_cipher_suites_from_cmdl(cmdl_args);
  FLEA_THR_BEG_FUNC();

  if(cfg.trusted_certs.size() == 0)
  {
    throw test_utils_exceptn_t("need to provide at least one trusted cert");
  }
  for(auto& cert_vec : cfg.trusted_certs)
  {
    FLEA_CCALL(
      THR_flea_cert_store_t__add_trusted_cert(
        trust_store__pt,
        &cert_vec[0],
        cert_vec.size()
      )
    );
  }
  if(cfg.own_certs.size() != 1)
  {
    throw test_utils_exceptn_t("own_certs so far only supports a single cert");
  }

  if(cfg.own_ca_chain.size() + 1 > *cert_chain_len)
  {
    throw test_utils_exceptn_t("number of ca certs too large");
  }
  *cert_chain_len = cfg.own_ca_chain.size() + 1;

  cert_chain[0].data__pcu8 = &(cfg.own_certs[0])[0];
  cert_chain[0].len__dtl   = cfg.own_certs[0].size();
  for(unsigned i = 0; i < cfg.own_ca_chain.size(); i++)
  {
    // std::cout << "adding to own_ca_chain" << std::endl;
    cert_chain[i + 1].data__pcu8 = &(cfg.own_ca_chain[i])[0];
    cert_chain[i + 1].len__dtl   = cfg.own_ca_chain[i].size();
  }


  server_key->data__pcu8 = &cfg.server_key_vec[0];
  server_key->len__dtl   = cfg.server_key_vec.size();

  FLEA_THR_FIN_SEC_empty();
} // THR_flea_tls_tool_set_tls_cfg

#endif // ifdef FLEA_HAVE_TLS
