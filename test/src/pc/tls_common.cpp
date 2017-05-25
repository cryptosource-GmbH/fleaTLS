/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/tls.h"
#include "pc/test_pc.h"
#include "pc/test_util.h"

#ifdef FLEA_HAVE_TLS
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
