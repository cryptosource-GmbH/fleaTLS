/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/tls.h"
#include "flea/array_util.h"
#include "flea/byte_vec.h"
#include "pc/test_pc.h"
#include "pc/test_util.h"
#include "internal/common/tls/tls_common.h"
#include "internal/common/tls/tls_common_ecc.h"
#include <iostream>

using namespace std;

#ifdef FLEA_HAVE_TLS

/*
 * struct cipher_suite_name_and_value_t
 * {
 * std::string name;
 * flea_u16_t  value;
 * } ;*/

std::map<string, flea_tls__cipher_suite_id_t> cipher_suite_name_value_map__t = {
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA
  {"TLS_RSA_WITH_AES_128_CBC_SHA",          flea_tls_rsa_with_aes_128_cbc_sha         },
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA
  {"TLS_RSA_WITH_AES_256_CBC_SHA",          flea_tls_rsa_with_aes_256_cbc_sha         },
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA256
  {"TLS_RSA_WITH_AES_128_CBC_SHA256",       flea_tls_rsa_with_aes_128_cbc_sha256      },
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA256
  {"TLS_RSA_WITH_AES_256_CBC_SHA256",       flea_tls_rsa_with_aes_256_cbc_sha256      },
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_GCM_SHA256
  {"TLS_RSA_WITH_AES_128_GCM_SHA256",       flea_tls_rsa_with_aes_128_gcm_sha256      },
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_GCM_SHA384
  {"TLS_RSA_WITH_AES_256_GCM_SHA384",       flea_tls_rsa_with_aes_256_gcm_sha384      },
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",    flea_tls_ecdhe_rsa_with_aes_128_cbc_sha   },
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",    flea_tls_ecdhe_rsa_with_aes_256_cbc_sha   },
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", flea_tls_ecdhe_rsa_with_aes_128_cbc_sha256},
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", flea_tls_ecdhe_rsa_with_aes_256_cbc_sha384},
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", flea_tls_ecdhe_rsa_with_aes_128_gcm_sha256},
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", flea_tls_ecdhe_rsa_with_aes_256_gcm_sha384}
# endif
};

std::map<string, flea_ec_dom_par_id_t> curve_id_name_value_map__t = {
  {"secp160r1",       flea_secp160r1      },
  {"secp160r2",       flea_secp160r2      },
  {"secp192r1",       flea_secp192r1      },
  {"secp224r1",       flea_secp224r1      },
  {"secp256r1",       flea_secp256r1      },
  {"secp384r1",       flea_secp384r1      },
  {"secp521r1",       flea_secp521r1      },
  {"brainpoolP256r1", flea_brainpoolP256r1},
  {"brainpoolP384r1", flea_brainpoolP384r1},
  {"brainpoolP512r1", flea_brainpoolP512r1}
};

std::map<string, flea_u8_t> sig_algs_map__t = {
  {"RSA", flea_rsa_pkcs1_v1_5_sign}
};

std::map<string, flea_u8_t> hash_algs_map__t = {
# ifdef FLEA_HAVE_SHA1
  {"SHA1",   flea_sha1  },
# endif
  {"SHA224", flea_sha224},
  {"SHA256", flea_sha256},
# ifdef FLEA_HAVE_SHA384_512
  {"SHA384", flea_sha384},
  {"SHA512", flea_sha512},
# endif
};

namespace {
  std::vector<flea_ec_dom_par_id_t> get_allowed_ecc_curves_from_cmdl(property_set_t const& cmdl_args)
  {
    flea_u8_t dummy[2];

    std::vector<flea_ec_dom_par_id_t> result;
# ifdef FLEA_HAVE_TLS_ECC
    if(cmdl_args.have_index("allowed_curves"))
    {
      std::vector<string> strings = tokenize_string(cmdl_args.get_property_as_string("allowed_curves"), ',');
      for(string s : strings)
      {
        // const flea_ec_dom_par_id_t* ptr;
        auto it = curve_id_name_value_map__t.find(s);
        if(it == curve_id_name_value_map__t.end() ||
          THR_flea_tls__map_flea_curve_to_curve_bytes((flea_ec_dom_par_id_t) it->second, dummy))
        {
          throw test_utils_exceptn_t("specified cipher suite '" + s + "' not configured");
        }
        result.push_back(curve_id_name_value_map__t[s]);
      }
    }
    else
    {
      for(auto & entry : curve_id_name_value_map__t)
      {
        flea_ec_dom_par_id_t id = entry.second;
        // const flea_tls__cipher_suite_t* ptr;
        if(!THR_flea_tls__map_flea_curve_to_curve_bytes((flea_ec_dom_par_id_t) id, dummy))
        {
          // std::cout << "adding curve " << entry.first << std::endl;
          result.push_back(id);
        }
      }
    }
# endif // ifdef FLEA_HAVE_TLS_ECC
    return result;
  } // get_allowed_ecc_curves_from_cmdl

  std::vector<flea_tls_sigalg_e> get_allowed_sig_algs_from_cmdl(property_set_t const& cmdl_args)
  {
    flea_u8_t dummy;

    std::vector<flea_tls_sigalg_e> result;
    if(cmdl_args.have_index("allowed_sig_algs"))
    {
      std::vector<string> strings = tokenize_string(cmdl_args.get_property_as_string("allowed_sig_algs"), ',');
      for(string s : strings)
      {
        flea_tls_sigalg_e sig_alg;
        std::vector<string> alg_pair = tokenize_string(s, '-');
        auto it  = hash_algs_map__t.find(alg_pair[0]);
        auto it2 = sig_algs_map__t.find(alg_pair[1]);
        if(it == hash_algs_map__t.end() ||
          THR_flea_tls__map_flea_hash_to_tls_hash((flea_hash_id_t) it->second, &dummy))
        {
          throw test_utils_exceptn_t(
                  "specified hash algorithm '" + alg_pair[0] + "' (in '" + s + "')" + " not configured"
          );
        }
        // result.push_back(it->second);
        sig_alg = (flea_tls_sigalg_e) (it->second << 8);
        if(it2 == sig_algs_map__t.end() ||
          THR_flea_tls__map_flea_sig_to_tls_sig((flea_pk_scheme_id_t) it2->second, &dummy))
        {
          throw test_utils_exceptn_t(
                  "specified sig algorithm '" + alg_pair[1] + "' (in '" + s + "')" + " not configured"
          );
        }
        sig_alg = (flea_tls_sigalg_e) (((flea_u32_t) sig_alg) | it2->second);
        result.push_back(sig_alg);
      }
    }
    else
    {
      // TODO: don't set anything? (=> client can't do ECDHE, will not default
      // to sha1)

      // for compatibility reasons with other tests, for now add SHA1-RSA,
      // SHA256-RSA

      // result.push_back(((flea_u8_t) flea_sha256 << 8) | ((flea_u8_t) flea_rsa_pkcs1_v1_5_sign));
      result.push_back(flea_tls_sigalg_rsa_sha256);

      // result.push_back(((flea_u8_t) flea_sha1 << 8) | ((flea_u8_t) flea_rsa_pkcs1_v1_5_sign));
      result.push_back(flea_tls_sigalg_rsa_sha1);
    }
    return result;
  } // get_allowed_sig_algs_from_cmdl

  std::vector<flea_tls__cipher_suite_id_t> get_cipher_suites_from_cmdl(property_set_t const& cmdl_args)
  {
    std::vector<flea_tls__cipher_suite_id_t> result;
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
        flea_tls__cipher_suite_id_t id = entry.second;
        const flea_tls__cipher_suite_t* ptr;
        if(!THR_flea_tls_get_cipher_suite_by_id(id, &ptr))
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

  static flea_u32_t string_to_rev_chk_flags(std::string const& s)
  {
    if(s == "all")
    {
      return 0;
    }
    else if((s == "") || (s == "none"))
    {
      return flea_tls_flag__rev_chk_mode__check_none;
    }
    else if(s == "only_ee")
    {
      return flea_tls_flag__rev_chk_mode__check_only_ee;
    }
    throw test_utils_exceptn_t("invalid value for property 'rev_chk': '" + s + "'");
  }
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
  cfg.flags = (flea_tls_flag_e) 0;


  std::string read_mode_s = cmdl_args.get_property_as_string_default_empty("app_data_read_mode");
  cfg.read_size_for_app_data = cmdl_args.get_property_as_u32_default("app_data_read_size", 20000);

  if(read_mode_s == "full")
  {
    cfg.read_mode_for_app_data = flea_read_full;
  }
  else if(read_mode_s == "" || read_mode_s == "nonblocking")
  {
    cfg.read_mode_for_app_data = flea_read_nonblocking;
  }
  else if(read_mode_s == "blocking")
  {
    cfg.read_mode_for_app_data = flea_read_blocking;
  }
  else
  {
    throw test_utils_exceptn_t("invalid value for app_data_read_mode");
  }


  cfg.trusted_certs = cmdl_args.get_bin_file_list_property("trusted");
  cfg.own_certs     = cmdl_args.get_bin_file_list_property("own_certs");
  if(cfg.own_certs.size())
  {
    cfg.server_key_vec = cmdl_args.get_bin_file("own_private_key");
    cfg.own_ca_chain   = cmdl_args.get_bin_file_list_property("own_ca_chain");
  }
  else
  {
    if(cmdl_args.have_index("own_private_key") || cmdl_args.have_index("own_ca_chain"))
    {
      throw test_utils_exceptn_t(
              "neither --own_private_key nor --own_ca_chain may be specified if --own_certs is absent or empty"
      );
    }
  }
  cfg.flags |= string_to_rev_chk_flags(cmdl_args.get_property_as_string_default_empty("rev_chk"));
  cfg.crls   = cmdl_args.get_bin_file_list_property("crls");
  for(auto &crl : cfg.crls)
  {
    /*flea_byte_vec_t bv;// = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE ;
    flea_byte_vec_t__INIT(&bv);
    flea_byte_vec_t__set_ref(&bv, &crl[0], crl.size());*/
    flea_ref_cu8_t ref;
    ref.data__pcu8 = &crl[0];
    ref.len__dtl   = crl.size();
    cfg.crls_refs.push_back(ref);
  }

  cfg.cipher_suites    = get_cipher_suites_from_cmdl(cmdl_args);
  cfg.allowed_curves   = get_allowed_ecc_curves_from_cmdl(cmdl_args);
  cfg.allowed_sig_algs = get_allowed_sig_algs_from_cmdl(cmdl_args);

  cfg.flags |= reneg_flag_from_string(cmdl_args.get_property_as_string_default_empty("reneg_mode"));

  FLEA_THR_BEG_FUNC();

  /*if(cfg.trusted_certs.size() == 0)
   * {
   * throw test_utils_exceptn_t("need to provide at least one trusted cert");
   * }*/
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
  if(cfg.own_certs.size() > 1)
  {
    throw test_utils_exceptn_t("own_certs so far only supports a single cert");
  }

  if(cfg.own_ca_chain.size() + 1 > *cert_chain_len)
  {
    throw test_utils_exceptn_t("number of ca certs too large");
  }
  if(cfg.own_certs.size())
  {
    *cert_chain_len = cfg.own_ca_chain.size() + 1;
    cert_chain[0].data__pcu8 = &(cfg.own_certs[0])[0];
    cert_chain[0].len__dtl   = cfg.own_certs[0].size();
    for(unsigned i = 0; i < cfg.own_ca_chain.size(); i++)
    {
      cert_chain[i + 1].data__pcu8 = &(cfg.own_ca_chain[i])[0];
      cert_chain[i + 1].len__dtl   = cfg.own_ca_chain[i].size();
    }

    server_key->data__pcu8 = &cfg.server_key_vec[0];
    server_key->len__dtl   = cfg.server_key_vec.size();
  }
  else
  {
    server_key->data__pcu8 = NULL;
    server_key->len__dtl   = 0;
    *cert_chain_len        = 0;
  }


  FLEA_THR_FIN_SEC_empty();
} // THR_flea_tls_tool_set_tls_cfg

static std::string rcu8_to_string(flea_ref_cu8_t* ref__prcu8)
{
  char buf__as8[1000];

  if(ref__prcu8->len__dtl >= sizeof(buf__as8))
  {
    return std::string("excessiv data length");
  }
  memcpy(buf__as8, ref__prcu8->data__pcu8, ref__prcu8->len__dtl);
  buf__as8[ref__prcu8->len__dtl] = 0;
  std::string result(static_cast<const char*>(buf__as8));
  return result;
}

static std::string cert_info_to_string(const flea_x509_cert_ref_t* cert_ref__pt)
{
  flea_dn_cmpnt_e dn_comps__ace[] = {
    flea_dn_cmpnt_cn,
    flea_dn_cmpnt_country,
    flea_dn_cmpnt_org,
    flea_dn_cmpnt_org_unit,
# ifdef FLEA_HAVE_X509_DN_DETAILS
    flea_dn_cmpnt_dn_qual,
    flea_dn_cmpnt_locality_name,
    flea_dn_cmpnt_state_or_province,
    flea_dn_cmpnt_serial_number,
    flea_dn_cmpnt_domain_cmpnt_attrib
# endif // ifdef FLEA_HAVE_X509_DN_DETAILS
  };

  std::string dn_comps_strings[] = {
    "cn",
    "country",
    "org",
    "org_unit",
# ifdef FLEA_HAVE_X509_DN_DETAILS
    "dn_qual",
    "locality_name",
    "state_or_province",
    "serial_number",
    "domain_cmpnt_attrib"
# endif // ifdef FLEA_HAVE_X509_DN_DETAILS
  };
  std::string subject_str, issuer_str;
  for(unsigned i = 0; i < FLEA_NB_ARRAY_ENTRIES(dn_comps__ace); i++)
  {
    flea_ref_cu8_t ref__rcu8;
    std::string this_label;
    if(i != 0)
    {
      this_label += "\n";
    }
    this_label  += "    ";
    this_label  += dn_comps_strings[i] + "=";
    issuer_str  += this_label;
    subject_str += this_label;
    if(THR_flea_x509_cert_ref_t__get_issuer_dn_component(cert_ref__pt, dn_comps__ace[i], &ref__rcu8))
    {
      issuer_str += "error accessing dn component\n";
    }
    issuer_str += rcu8_to_string(&ref__rcu8);
    if(THR_flea_x509_cert_ref_t__get_subject_dn_component(cert_ref__pt, dn_comps__ace[i], &ref__rcu8))
    {
      subject_str += "error accessing dn component\n";
    }
    subject_str += rcu8_to_string(&ref__rcu8);
  }
  return "  subject DN: \n" + subject_str + "\n";

  return "  issuer DN: \n" + issuer_str + "\n";
} // cert_info_to_string

void flea_tls_test_tool_print_peer_cert_info(
  flea_tls_client_ctx_t* client_ctx_mbn__pt,
  flea_tls_server_ctx_t* server_ctx_mbn__pt,
  server_params_t*       server_params_mbn__pt
)
{
  std::string s;
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
  const flea_x509_cert_ref_t* ee_ref__pt = nullptr;
  if(client_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_CLIENT
    if(flea_tls_client_ctx_t__have_peer_ee_cert_ref(client_ctx_mbn__pt))
    {
      ee_ref__pt = flea_tls_client_ctx_t__get_peer_ee_cert_ref(client_ctx_mbn__pt);
    }
#  endif // ifdef FLEA_HAVE_TLS_CLIENT
  }
  else if(server_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_SERVER
    if(flea_tls_server_ctx_t__have_peer_ee_cert_ref(server_ctx_mbn__pt))
    {
      ee_ref__pt = flea_tls_server_ctx_t__get_peer_ee_cert_ref(server_ctx_mbn__pt);
    }
#  endif // ifdef FLEA_HAVE_TLS_SERVER
  }
  if(ee_ref__pt)
  {
    s += "EE cert:\n";
    s += cert_info_to_string(ee_ref__pt);
  }
# endif // ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
  const flea_x509_cert_ref_t* root_ref__pt = nullptr;
  if(client_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_CLIENT
    if(flea_tls_client_ctx_t__have_peer_root_cert_ref(client_ctx_mbn__pt))
    {
      root_ref__pt = flea_tls_client_ctx_t__get_peer_root_cert_ref(client_ctx_mbn__pt);
    }
#  endif // ifdef FLEA_HAVE_TLS_CLIENT
  }
  else if(server_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_SERVER
    if(flea_tls_server_ctx_t__have_peer_root_cert_ref(server_ctx_mbn__pt))
    {
      root_ref__pt = flea_tls_server_ctx_t__get_peer_root_cert_ref(server_ctx_mbn__pt);
    }
#  endif // ifdef FLEA_HAVE_TLS_SERVER
  }
  if(root_ref__pt)
  {
    s += "root cert:\n";
    s += cert_info_to_string(root_ref__pt);
  }
# endif // ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
  if(server_params_mbn__pt)
  {
    server_params_mbn__pt->write_output_string(s);
  }
  else
  {
    std::cout << s;
  }
} // flea_tls_test_tool_print_peer_cert_info

#endif // ifdef FLEA_HAVE_TLS
