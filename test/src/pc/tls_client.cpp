/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <cstring>
#include <stdio.h>
#include <sys/time.h> // Linux specific

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_addr
#include <unistd.h>    // for close

#include "pc/test_util.h"
#include "flea/tls.h"
#include "pc/test_pc.h"
#include "pltf_support/tcpip_stream.h"
#include "internal/common/tls/tls_common.h"
#include "flea/array_util.h"
#include "flea/byte_vec.h"
#include "flea/pkcs8.h"
#include "flea/tls_client.h"

#ifdef FLEA_HAVE_TLS

static flea_err_t THR_flea_start_tls_client(
  property_set_t const       & cmdl_args,
  flea_tls_client_session_t* client_session__pt
)
{
  flea_rw_stream_t rw_stream__t;
  flea_cert_store_t trust_store__t;

  flea_tls_client_ctx_t tls_ctx;

  flea_ref_cu8_t hostname;
  flea_ref_cu8_t* hostname_p = NULL;

  flea_ref_cu8_t cert_chain[10];
  flea_ref_cu8_t client_key__t;

  flea_al_u16_t cert_chain_len = FLEA_NB_ARRAY_ENTRIES(cert_chain);

  flea_ref_cu16_t cipher_suites_ref;

  flea_ref_cu8_t allowed_ecc_curves__rcu8;
  flea_ref_cu8_t allowed_sig_algs__rcu8;
  tls_test_cfg_t tls_cfg;
  flea_host_id_type_e host_type;
  linux_socket_stream_ctx_t sock_stream_ctx;
  flea_private_key_t privkey__t;

  std::string hostname_s;
  FLEA_THR_BEG_FUNC();
  flea_private_key_t__INIT(&privkey__t);
  flea_rw_stream_t__INIT(&rw_stream__t);
  flea_tls_client_ctx_t__INIT(&tls_ctx);
  flea_cert_store_t__INIT(&trust_store__t);
  FLEA_CCALL(THR_flea_cert_store_t__ctor(&trust_store__t));
  if(cmdl_args.have_index("hostname") || cmdl_args.have_index("ip_addr"))
  {
    std::string index;
    if(cmdl_args.have_index("hostname"))
    {
      index     = "hostname";
      host_type = flea_host_dnsname;
    }
    else
    {
      index     = "ip_addr";
      host_type = flea_host_ipaddr;
    }
    hostname_s = cmdl_args.get_property_as_string(index);

    if(!cmdl_args.have_index("no_hostn_ver"))
    {
      hostname_p = &hostname;
      hostname.data__pcu8 = reinterpret_cast<const flea_u8_t*>(hostname_s.c_str());
      hostname.len__dtl   = static_cast<flea_dtl_t>(std::strlen(hostname_s.c_str()));
    }
  }
  else
  {
    throw("neither 'hostname' nor 'ip_addr' provided");
  }


  FLEA_CCALL(
    THR_flea_tls_tool_set_tls_cfg(
      &trust_store__t,
      cert_chain,
      &cert_chain_len,
      &client_key__t,
      cmdl_args,
      tls_cfg
    )
  );
  cipher_suites_ref.data__pcu16       = &tls_cfg.cipher_suites[0];
  cipher_suites_ref.len__dtl          = tls_cfg.cipher_suites.size();
  allowed_ecc_curves__rcu8.data__pcu8 = &tls_cfg.allowed_curves[0];
  allowed_ecc_curves__rcu8.len__dtl   = tls_cfg.allowed_curves.size();
  allowed_sig_algs__rcu8.data__pcu8   = &tls_cfg.allowed_sig_algs[0];
  allowed_sig_algs__rcu8.len__dtl     = tls_cfg.allowed_sig_algs.size();

  FLEA_CCALL(
    THR_flea_pltfif_tcpip__create_rw_stream_client(
      &rw_stream__t,
      &sock_stream_ctx,
      cmdl_args.get_property_as_u32("port"),
      cmdl_args.get_property_as_u32_default("read_timeout", 0),
      hostname_s.c_str(),
      host_type == flea_host_dnsname ? FLEA_TRUE : FLEA_FALSE
    )
  );

  if(client_key__t.len__dtl)
  {
    FLEA_CCALL(
      THR_flea_private_key_t__ctor_pkcs8(
        &privkey__t,
        client_key__t.data__pcu8,
        client_key__t.len__dtl
      )
    );
  }
  FLEA_CCALL(
    THR_flea_tls_client_ctx_t__ctor(
      &tls_ctx,
      &trust_store__t,
      hostname_p,
      host_type,
      &rw_stream__t,
      cert_chain_len ? cert_chain : NULL,
      cert_chain_len,
      client_key__t.len__dtl ? &privkey__t : NULL,
      &cipher_suites_ref,
      // tls_cfg.rev_chk_mode__e,
      &tls_cfg.crls_refs[0],
      tls_cfg.crls.size(),
      client_session__pt,
      &allowed_ecc_curves__rcu8,
      &allowed_sig_algs__rcu8,
      tls_cfg.flags | FLEA_TLS_CFG_FLAG__SHA1_CERT_SIGALG__ALLOW
    )
  );

  // printf("session was resumed = %u\n", client_session__pt->for_resumption__u8);
  flea_tls_test_tool_print_peer_cert_info(&tls_ctx, nullptr, nullptr);
  for(size_t i = 0; i < cmdl_args.get_property_as_u32_default("do_renegs", 0); i++)
  {
    std::cout << "renegotiation ...\n";
    flea_bool_t reneg_done__b;
    FLEA_CCALL(
      THR_flea_tls_client_ctx_t__renegotiate(
        &tls_ctx,
        &reneg_done__b,
        &trust_store__t,
        cert_chain,
        cert_chain_len,
        &cipher_suites_ref,
        &tls_cfg.crls_refs[0],
        tls_cfg.crls.size()
      )
    );
    if(reneg_done__b)
    {
      std::cout << "... done.\n";
    }
    else
    {
      std::cout << "... was rejected\n";
    }
  }
  while(cmdl_args.have_index("stay"))
  {
    flea_u8_t buf[100000];
    flea_al_u16_t buf_len = sizeof(buf) - 1;
    FLEA_CCALL(THR_flea_tls_client_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_blocking));
    FLEA_CCALL(THR_flea_tls_client_ctx_t__send_app_data(&tls_ctx, buf, buf_len));
    FLEA_CCALL(THR_flea_tls_client_ctx_t__flush_write_app_data(&tls_ctx));
    buf[buf_len] = 0;
    printf("received data: %s\n", buf);
    usleep(10000);
  }

  FLEA_THR_FIN_SEC(
    flea_tls_client_ctx_t__dtor(&tls_ctx);
    flea_rw_stream_t__dtor(&rw_stream__t);
    flea_cert_store_t__dtor(&trust_store__t);
    flea_private_key_t__dtor(&privkey__t);
  );
} // THR_flea_start_tls_client

int flea_start_tls_client(property_set_t const& cmdl_args)
{
  flea_err_t err = FLEA_ERR_FINE;
  flea_tls_client_session_t client_session__t;
  int retval = 0;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(serialized_session_t, 200);
  flea_tls_client_session_t__INIT(&client_session__t);

  flea_tls_client_session_t__ctor(&client_session__t);
  if(cmdl_args.have_index("session") && cmdl_args.have_index("session_in"))
  {
    throw test_utils_exceptn_t("provided both 'session' and 'session_in', which is not allowed");
  }
  else if(cmdl_args.have_index("session") || cmdl_args.have_index("session_in"))
  {
    std::vector<flea_u8_t> sid;
    if(cmdl_args.have_index("session"))
    {
      std::string s = cmdl_args.get_property_as_string("session");
      sid = hex_to_bin(s);
    }
    else if(cmdl_args.have_index("session_in"))
    {
      sid = read_bin_file(cmdl_args.get_property_as_string("session_in"));
    }
    err = THR_flea_tls_client_session_t_deserialize(&client_session__t, &sid[0], sid.size());
  }
  if(err != FLEA_ERR_FINE)
  {
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("error deserializing provided session");
  }
  else
  {
    if((err = THR_flea_start_tls_client(cmdl_args, &client_session__t)))
    {
      FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during tls client test\n", err);
      retval = 1;
    }

    err = THR_flea_tls_client_session_t__serialize(&client_session__t, &serialized_session_t);
    if(err)
    {
      FLEA_PRINTF_TEST_OUTP_1_SWITCHED("no valid session established, cannot generate session to store\n");
    }
    else
    {
      FLEA_PRINTF_TEST_OUTP_1_SWITCHED("session for resumption = ");
      std::string s = bin_to_hex(serialized_session_t.data__pu8, serialized_session_t.len__dtl);
      std::cout << s << std::endl;

      if(cmdl_args.have_index("session_out"))
      {
        write_bin_file(
          cmdl_args.get_property_as_string(
            "session_out"
          ),
          serialized_session_t.data__pu8,
          serialized_session_t.len__dtl
        );
      }
    }
    if(!retval)
    {
      FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    }
  }
  flea_tls_client_session_t__dtor(&client_session__t);
  flea_byte_vec_t__dtor(&serialized_session_t);
  return retval;
} // flea_start_tls_client

#endif // ifdef FLEA_HAVE_TLS
