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


std::map<string, flea_tls_cipher_suite_id_t> cipher_suite_name_value_map__t = {
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA
  {"TLS_RSA_WITH_AES_128_CBC_SHA",            flea_tls_rsa_with_aes_128_cbc_sha           },
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA
  {"TLS_RSA_WITH_AES_256_CBC_SHA",            flea_tls_rsa_with_aes_256_cbc_sha           },
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA256
  {"TLS_RSA_WITH_AES_128_CBC_SHA256",         flea_tls_rsa_with_aes_128_cbc_sha256        },
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA256
  {"TLS_RSA_WITH_AES_256_CBC_SHA256",         flea_tls_rsa_with_aes_256_cbc_sha256        },
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_GCM_SHA256
  {"TLS_RSA_WITH_AES_128_GCM_SHA256",         flea_tls_rsa_with_aes_128_gcm_sha256        },
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_GCM_SHA384
  {"TLS_RSA_WITH_AES_256_GCM_SHA384",         flea_tls_rsa_with_aes_256_gcm_sha384        },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      flea_tls_ecdhe_rsa_with_aes_128_cbc_sha     },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      flea_tls_ecdhe_rsa_with_aes_256_cbc_sha     },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   flea_tls_ecdhe_rsa_with_aes_128_cbc_sha256  },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   flea_tls_ecdhe_rsa_with_aes_256_cbc_sha384  },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   flea_tls_ecdhe_rsa_with_aes_128_gcm_sha256  },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   flea_tls_ecdhe_rsa_with_aes_256_gcm_sha384  },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha   },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha   },
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha256},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha384},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", flea_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256},
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", flea_tls_ecdhe_ecdsa_with_aes_256_gcm_sha384},
# endif
# ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_CBC_SHA
  {"TLS_PSK_WITH_AES_128_CBC_SHA",            flea_tls_psk_with_aes_128_cbc_sha           },
# endif
# ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_CBC_SHA
  {"TLS_PSK_WITH_AES_256_CBC_SHA",            flea_tls_psk_with_aes_256_cbc_sha           },
# endif
# ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_CBC_SHA256
  {"TLS_PSK_WITH_AES_128_CBC_SHA256",         flea_tls_psk_with_aes_128_cbc_sha256        },
# endif
# ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_CBC_SHA384
  {"TLS_PSK_WITH_AES_256_CBC_SHA384",         flea_tls_psk_with_aes_256_cbc_sha384        },
# endif
# ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_GCM_SHA256
  {"TLS_PSK_WITH_AES_128_GCM_SHA256",         flea_tls_psk_with_aes_128_gcm_sha256        },
# endif
# ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_GCM_SHA384
  {"TLS_PSK_WITH_AES_256_GCM_SHA384",         flea_tls_psk_with_aes_256_gcm_sha384        },
# endif
};

std::map<string, flea_ec_dom_par_id_e> curve_id_name_value_map__t = {
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

std::map<string, flea_pk_scheme_id_e> sig_algs_map__t = {
  {"RSA",   flea_rsa_pkcs1_v1_5_sign},
  {"ECDSA", flea_ecdsa_emsa1_asn1   },
};

std::map<string, flea_hash_id_e> hash_algs_map__t = {
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
  std::vector<flea_ec_dom_par_id_e> get_allowed_ecc_curves_from_cmdl(property_set_t const& cmdl_args)
  {
    std::vector<flea_ec_dom_par_id_e> result;

# ifdef FLEA_HAVE_TLS_CS_ECC
    flea_u8_t dummy[2];
    if(cmdl_args.have_index("allowed_curves"))
    {
      std::vector<string> strings = tokenize_string(cmdl_args.get_property_as_string("allowed_curves"), ',');
      for(string s : strings)
      {
        auto it = curve_id_name_value_map__t.find(s);
        if(it == curve_id_name_value_map__t.end() ||
          THR_flea_tls__map_flea_curve_to_curve_bytes((flea_ec_dom_par_id_e) it->second, dummy))
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
        flea_ec_dom_par_id_e id = entry.second;
        if(!THR_flea_tls__map_flea_curve_to_curve_bytes((flea_ec_dom_par_id_e) id, dummy))
        {
          result.push_back(id);
        }
      }
    }
# endif // ifdef FLEA_HAVE_TLS_CS_ECC
    return result;
  } // get_allowed_ecc_curves_from_cmdl

  flea_u8_t flea_tls_map_tls_hash_to_flea_hash__at[6][2] = {
# ifdef FLEA_HAVE_MD5
    {0x01, flea_md5   },
# endif
# ifdef FLEA_HAVE_SHA1
    {0x02, flea_sha1  },
# endif
    {0x03, flea_sha224},
    {0x04, flea_sha256},
# ifdef FLEA_HAVE_SHA384_512
    {0x05, flea_sha384},
    {0x06, flea_sha512}
# endif
  };
  static flea_err_e THR_flea_tls__map_flea_hash_to_tls_hash(
    flea_hash_id_e hash_id__t,
    flea_u8_t*     id__pu8
  )
  {
    FLEA_THR_BEG_FUNC();
    for(flea_u8_t i = 0; i < FLEA_NB_ARRAY_ENTRIES(flea_tls_map_tls_hash_to_flea_hash__at); i++)
    {
      if(flea_tls_map_tls_hash_to_flea_hash__at[i][1] == hash_id__t)
      {
        *id__pu8 = flea_tls_map_tls_hash_to_flea_hash__at[i][0];
        FLEA_THR_RETURN();
      }
    }
    FLEA_THROW("hash algorithm has no mapping for tls", FLEA_ERR_INT_ERR);
    FLEA_THR_FIN_SEC_empty();
  }

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
          THR_flea_tls__map_flea_hash_to_tls_hash((flea_hash_id_e) it->second, &dummy))
        {
          throw test_utils_exceptn_t(
                  "specified hash algorithm '" + alg_pair[0] + "' (in '" + s + "')" + " not configured"
          );
        }
        sig_alg = (flea_tls_sigalg_e) (it->second << 8);
        if(it2 == sig_algs_map__t.end() ||
          THR_flea_tls__map_flea_sig_to_tls_sig((flea_pk_scheme_id_e) it2->second, &dummy))
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
      std::map<string, flea_pk_scheme_id_e>::iterator pk_it;
      for(pk_it = sig_algs_map__t.begin(); pk_it != sig_algs_map__t.end(); pk_it++)
      {
        flea_u32_t pk = pk_it->second;
        std::map<string, flea_hash_id_e>::iterator hash_it;
        for(hash_it = hash_algs_map__t.begin(); hash_it != hash_algs_map__t.end(); hash_it++)
        {
          flea_u32_t hash = (hash_it->second << 8);
          result.push_back((flea_tls_sigalg_e) (hash | pk));
        }
      }
# if 0
#  ifdef FLEA_HAVE_RSA
      result.push_back(flea_tls_sigalg_rsa_sha256);
#   ifdef FLEA_HAVE_SHA1
      result.push_back(flea_tls_sigalg_rsa_sha1);
#   endif
#  endif // ifdef FLEA_HAVE_RSA
#  ifdef FLEA_HAVE_ECDSA
      result.push_back(flea_tls_sigalg_ecdsa_sha256);
#   ifdef FLEA_HAVE_SHA1
      result.push_back(flea_tls_sigalg_ecdsa_sha1);
#   endif

#  endif // ifdef FLEA_HAVE_ECDSA
# endif // if 0
    }
    return result;
  } // get_allowed_sig_algs_from_cmdl

  std::vector<flea_tls_cipher_suite_id_t> get_cipher_suites_from_cmdl(property_set_t const& cmdl_args)
  {
    std::vector<flea_tls_cipher_suite_id_t> result;

    if(cmdl_args.have_index("cipher_suites"))
    {
      std::vector<string> strings = tokenize_string(cmdl_args.get_property_as_string("cipher_suites"), ',');
      for(string s : strings)
      {
        const flea_tls__cipher_suite_t* ptr;
        auto it = cipher_suite_name_value_map__t.find(s);
        if(it == cipher_suite_name_value_map__t.end() ||
          THR_flea_tls_get_cipher_suite_by_id(static_cast<flea_tls_cipher_suite_id_t>(it->second), &ptr))
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
        flea_tls_cipher_suite_id_t id = entry.second;
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
    else if(/*(s == "") ||*/ (s == "none"))
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

socket_type_t get_socket_type(property_set_t const& props)
{
  if(use_dtls(props))
  {
    return udp;
  }
  else
  {
    return tcp;
  }
}

bool use_dtls(property_set_t const& props)
{
  std::string s = props.get_property_as_string("protocol_variant");
  if(s == "tls")
  {
    return false;
  }
  else if(s == "dtls")
  {
    return true;
  }
  throw test_utils_exceptn_t("invlalid protocol_variant provided: " + s);
}

std::string get_comma_seperated_list_of_supported_sig_algs()
{
  std::string result;
  std::map<string, flea_pk_scheme_id_e>::iterator pk_it;

  for(pk_it = sig_algs_map__t.begin(); pk_it != sig_algs_map__t.end(); pk_it++)
  {
    std::string pk = pk_it->first;
    std::map<string, flea_hash_id_e>::iterator hash_it;
    for(hash_it = hash_algs_map__t.begin(); hash_it != hash_algs_map__t.end(); hash_it++)
    {
      if(result != "")
      {
        result += ",";
      }
      std::string hash = hash_it->first;
      result += (pk + "-" + hash);
    }
  }
  return result;
}

flea_err_e THR_flea_tls_tool_set_tls_cfg(
  flea_cert_store_t*  trust_store__pt,
  flea_ref_cu8_t*     cert_chain,
  flea_al_u16_t*      cert_chain_len,
  flea_ref_cu8_t*     server_key,
  property_set_t const& cmdl_args,
  tls_test_cfg_t      & cfg
)
{
  cfg.flags = (flea_tls_flag_e) 0;


  std::string read_mode_s = cmdl_args.get_property_as_string("app_data_read_mode");
  cfg.read_size_for_app_data = cmdl_args.get_property_as_u32("app_data_read_size");

  if(read_mode_s == "full")
  {
    cfg.read_mode_for_app_data = flea_read_full;
  }
  else if(read_mode_s == "nonblocking")
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
  cfg.flags |= string_to_rev_chk_flags(cmdl_args.get_property_as_string("rev_chk"));
  cfg.crls   = cmdl_args.get_bin_file_list_property("crls");
  for(auto &crl : cfg.crls)
  {
    flea_ref_cu8_t ref;
    ref.data__pcu8 = &crl[0];
    ref.len__dtl   = crl.size();
    cfg.crls_refs.push_back(ref);
  }

  cfg.cipher_suites    = get_cipher_suites_from_cmdl(cmdl_args);
  cfg.allowed_curves   = get_allowed_ecc_curves_from_cmdl(cmdl_args);
  cfg.allowed_sig_algs = get_allowed_sig_algs_from_cmdl(cmdl_args);

  cfg.flags |= reneg_flag_from_string(cmdl_args.get_property_as_string("reneg_mode"));

  cfg.flags |= min_key_strength_from_string(cmdl_args.get_property_as_string("min_key_strength"));


  if(cmdl_args.have_index("accept_untrusted"))
  {
    cfg.flags |= flea_tls_flag__accept_untrusted_peer;
  }

  FLEA_THR_BEG_FUNC();

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

  if(use_dtls(cmdl_args))
  {
    cfg.flags |= flea_tls_flag__allow_dtls1_2;
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
  flea_tls_clt_ctx_t* client_ctx_mbn__pt,
  flea_tls_srv_ctx_t* server_ctx_mbn__pt,
  server_params_t*    server_params_mbn__pt
)
{
  std::string s;

# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
  const flea_x509_cert_ref_t* ee_ref__pt = nullptr;
  if(client_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_CLIENT
    if(flea_tls_clt_ctx_t__have_peer_ee_cert_ref(client_ctx_mbn__pt))
    {
      ee_ref__pt = flea_tls_clt_ctx_t__get_peer_ee_cert_ref(client_ctx_mbn__pt);
    }
#  endif // ifdef FLEA_HAVE_TLS_CLIENT
  }
  else if(server_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_SERVER
    if(flea_tls_srv_ctx_t__have_peer_ee_cert_ref(server_ctx_mbn__pt))
    {
      ee_ref__pt = flea_tls_srv_ctx_t__get_peer_ee_cert_ref(server_ctx_mbn__pt);
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
    if(flea_tls_clt_ctx_t__have_peer_root_cert_ref(client_ctx_mbn__pt))
    {
      root_ref__pt = flea_tls_clt_ctx_t__get_peer_root_cert_ref(client_ctx_mbn__pt);
    }
#  endif // ifdef FLEA_HAVE_TLS_CLIENT
  }
  else if(server_ctx_mbn__pt)
  {
#  ifdef FLEA_HAVE_TLS_SERVER
    if(flea_tls_srv_ctx_t__have_peer_root_cert_ref(server_ctx_mbn__pt))
    {
      root_ref__pt = flea_tls_srv_ctx_t__get_peer_root_cert_ref(server_ctx_mbn__pt);
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

flea_err_e dummy_process_identity_hint(
  flea_byte_vec_t* psk_vec__pt,
  const flea_u8_t* psk_identity_hint__pu8,
  const flea_u16_t psk_identity_hint_len__u16
)
{
  FLEA_THR_BEG_FUNC();
  std::vector<flea_u8_t> hex =
    hex_to_bin(std::string(psk_identity_hint__pu8, psk_identity_hint__pu8 + psk_identity_hint_len__u16));
  FLEA_CCALL(
    THR_flea_byte_vec_t__append(
      psk_vec__pt,
      hex.data(),
      hex.size()
      // psk_identity_hint__pu8,
      // psk_identity_hint_len__u16
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

#endif // ifdef FLEA_HAVE_TLS
