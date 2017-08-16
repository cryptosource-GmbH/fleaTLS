/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "test_data_x509_certs.h"
#include "flea/hostn_ver.h"

#include <string.h>

flea_err_t THR_flea_test_dec_tls_server_cert_broken()
{
  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  if(!THR_flea_x509_cert_ref_t__ctor(
      &cert_ref__t,
      flea_test_cert_tls_server_broken,
      sizeof(flea_test_cert_tls_server_broken)
    ))
  {
    FLEA_THROW("no excpetion in broken cert", FLEA_ERR_FAILED_TEST);
  }
  // printf("cert_ref size = %u\n", sizeof(cert_ref__t));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_dec_tls_server_issuer_cert()
{
  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_x509_cert_ref_t__ctor(
      &cert_ref__t,
      flea_test_cert_issuer_of_tls_server_1__cau8,
      sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)
    )
  );

  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
  );
}

flea_err_t THR_flea_test_dec_tls_server_cert()
{
  const char* hostname__cs        = "internal.cryptosource.de";
  const char* wrong_hostname__cs  = "internal.cryptosource.dd";
  const char* wrong_hostname2__cs = "jnternal.cryptosource.de";

  flea_u8_t ipaddr__acu8 []       = {94, 16, 81, 15};
  flea_u8_t wrong_ipaddr__acu8 [] = {94, 16, 81, 14};

  /*flea_ref_cu8_t ipaddr__rcu8       = {ipaddr__acu8, sizeof(ipaddr__acu8)};
   * flea_ref_cu8_t wrong_ipaddr__rcu8 = {wrong_ipaddr__acu8, sizeof(wrong_ipaddr__acu8)};*/
  FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(ipaddr_vec__t, ipaddr__acu8, sizeof(ipaddr__acu8));
  FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
    wrong_ipaddr_vec__t,
    wrong_ipaddr__acu8,
    sizeof(wrong_ipaddr__acu8)
  );

  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, test_cert_tls_server_1, sizeof(test_cert_tls_server_1)));

  FLEA_CCALL(THR_flea_x509__verify_tls_server_id_cstr(hostname__cs, flea_host_dnsname, &cert_ref__t));
  FLEA_CCALL(THR_flea_x509__verify_tls_server_id(&ipaddr_vec__t, flea_host_ipaddr, &cert_ref__t));

  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=
    THR_flea_x509__verify_tls_server_id_cstr(wrong_hostname__cs, flea_host_dnsname, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=
    THR_flea_x509__verify_tls_server_id_cstr(wrong_hostname2__cs, flea_host_dnsname, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=
    THR_flea_x509__verify_tls_server_id(&wrong_ipaddr_vec__t, flea_host_ipaddr, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }

  if(flea_x509_cert_ref_t__HAS_PATH_LEN_LIMIT(&cert_ref__t) ||
    flea_x509_cert_ref_t__IS_CA(&cert_ref__t))
  {
    FLEA_THROW("error decoding empty basic_constraints extensions", FLEA_ERR_FAILED_TEST);
  }

  if(!flea_x509_cert_ref_t__has_extended_key_usages(
      &cert_ref__t,
      (flea_ext_key_usage_e) (flea_eku_server_auth | flea_eku_client_auth),
      flea_key_usage_explicit
    ))
  {
    FLEA_THROW("error decoding EKU", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
  );
} /* THR_flea_test_dec_tls_server_cert */

flea_err_t THR_flea_test_dec_ca_cert()
{
  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  flea_ref_cu8_t ref__rcu8;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, test_ca_cert_1, sizeof(test_ca_cert_1)));
  if(flea_x509_cert_ref_t__GET_CERT_VERSION(&cert_ref__t) != 3)
  {
    FLEA_THROW("parsed version number is incorrect", FLEA_ERR_FAILED_TEST);
  }
  flea_x509_cert_ref_t__GET_SERIAL_NUMBER(&cert_ref__t, &ref__rcu8);
  if(ref__rcu8.len__dtl != 1 || ref__rcu8.data__pcu8[0] != 62)
  {
    FLEA_THROW("parsed serial number is incorrect", FLEA_ERR_FAILED_TEST);
  }
  flea_x509_cert_ref_t__GET_SIGALG_OID(&cert_ref__t, &ref__rcu8);
  if(ref__rcu8.len__dtl != 9 ||
    ref__rcu8.data__pcu8[0] != 0x2A)
  {
    FLEA_THROW("parsed tbs sig alg is incorrect", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_x509_cert_ref_t__get_issuer_dn_component(&cert_ref__t, flea_dn_cmpnt_country, &ref__rcu8));
  if(ref__rcu8.len__dtl != 2 || ref__rcu8.data__pcu8[0] != 'U' ||
    ref__rcu8.data__pcu8[1] != 'S')
  {
    FLEA_THROW("parsed issuer country is incorrect", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_x509_cert_ref_t__get_issuer_dn_component(&cert_ref__t, flea_dn_cmpnt_org_unit, &ref__rcu8));
  if(ref__rcu8.len__dtl != 0)
  {
    FLEA_THROW("non existing issuer org unit is incorrect", FLEA_ERR_FAILED_TEST);
  }
#ifdef FLEA_X509_CERT_REF_WITH_DETAILS
  if(flea_x509_cert_ref_t__HAS_ISSUER_UNIQUE_ID(&cert_ref__t))
  {
    FLEA_THROW("issuer unique id error", FLEA_ERR_FAILED_TEST);
  }
  else
  {
    flea_x509_cert_ref_t__GET_REF_TO_ISSUER_UNIQUE_ID_AS_BIT_STRING(&cert_ref__t, &ref__rcu8);
  }
#endif
  if(cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.len__dtl != 2 ||
    cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.data__pu8[0] != 0x05 ||
    cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.data__pu8[1] != 0x00)
  {
    FLEA_THROW("error decoding null params", FLEA_ERR_FAILED_TEST);
  }
  if(!flea_x509_cert_ref_t__has_key_usages(
      &cert_ref__t,
      (flea_key_usage_e) (flea_ku_crl_sign | flea_ku_key_cert_sign),
      flea_key_usage_explicit
    ))
  {
    FLEA_THROW("error positive KU", FLEA_ERR_FAILED_TEST);
  }
  if(!flea_x509_cert_ref_t__has_key_usages(
      &cert_ref__t,
      (flea_key_usage_e) (flea_ku_crl_sign | flea_ku_key_cert_sign),
      flea_key_usage_implicit
    ))
  {
    FLEA_THROW("error positive KU", FLEA_ERR_FAILED_TEST);
  }
  if(flea_x509_cert_ref_t__has_key_usages(
      &cert_ref__t,
      flea_ku_data_encipherment,
      flea_key_usage_explicit
    ))
  {
    FLEA_THROW("error negative KU", FLEA_ERR_FAILED_TEST);
  }
  if(flea_x509_cert_ref_t__has_key_usages(
      &cert_ref__t,
      flea_ku_data_encipherment,
      flea_key_usage_implicit
    ))
  {
    FLEA_THROW("error negative KU", FLEA_ERR_FAILED_TEST);
  }

#ifdef FLEA_X509_CERT_REF_WITH_DETAILS
  if(cert_ref__t.extensions__t.subj_key_id__t.len__dtl != 20)
  {
    FLEA_THROW("error len of skid", FLEA_ERR_FAILED_TEST);
  }
#endif
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
  );
} /* THR_flea_test_dec_ca_cert */
