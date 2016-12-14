/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/data_source.h"
#include "flea/ber_dec.h"
#include "flea/x509.h"
#include "test_data_x509_certs.h"
#include "flea/hostn_ver.h"

#include <string.h>

flea_err_t THR_flea_test_dec_tls_server_cert_broken()
{
  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  if(!THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, flea_test_cert_tls_server_broken, sizeof(flea_test_cert_tls_server_broken)))
  {
    FLEA_THROW("no excpetion in broken cert", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_dec_tls_server_issuer_cert()
{
  const flea_u8_t serial__cau8 [] = { 0x00, 0x83, 0x01, 0xC0, 0x9D, 0x7D, 0xF7, 0xC9, 0x7D};

  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, flea_test_cert_issuer_of_tls_server_1__cau8, sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)));
  if(cert_ref__t.extensions__t.auth_key_id__t.auth_cert_serial_number__t.data__pcu8 == NULL)
  {
    FLEA_THROW("error with serial from AKI: absent", FLEA_ERR_FAILED_TEST);

  }
  if(cert_ref__t.extensions__t.auth_key_id__t.auth_cert_serial_number__t.len__dtl != 9 || memcmp(serial__cau8, cert_ref__t.extensions__t.auth_key_id__t.auth_cert_serial_number__t.data__pcu8, sizeof(serial__cau8)))
  {
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("aki serial len = %u\n", cert_ref__t.extensions__t.auth_key_id__t.auth_cert_serial_number__t.len__dtl);
    FLEA_THROW("error with serial from AKI: len/value", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
      );
}
flea_err_t THR_flea_test_dec_tls_server_cert()
{
  const char *hostname__cs = "internal.cryptosource.de";
  const char *wrong_hostname__cs = "internal.cryptosource.dd";
  const char *wrong_hostname2__cs = "jnternal.cryptosource.de";

  flea_u8_t ipaddr__acu8 [] = {94,16,81,15};
  flea_u8_t wrong_ipaddr__acu8 [] = {94,16,81,14};
  flea_ref_cu8_t ipaddr__rcu8 = {ipaddr__acu8, sizeof(ipaddr__acu8)};
  flea_ref_cu8_t wrong_ipaddr__rcu8 = {wrong_ipaddr__acu8, sizeof(wrong_ipaddr__acu8)};

  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, test_cert_tls_server_1, sizeof(test_cert_tls_server_1)));

  FLEA_CCALL(THR_flea_x509__verify_tls_server_id_cstr(hostname__cs, flea_host_dnsname, &cert_ref__t));
  FLEA_CCALL(THR_flea_x509__verify_tls_server_id(&ipaddr__rcu8, flea_host_ipaddr, &cert_ref__t));
  
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=  THR_flea_x509__verify_tls_server_id_cstr(wrong_hostname__cs, flea_host_dnsname, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=  THR_flea_x509__verify_tls_server_id_cstr(wrong_hostname2__cs, flea_host_dnsname, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH != THR_flea_x509__verify_tls_server_id(&wrong_ipaddr__rcu8, flea_host_ipaddr, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }


  /*if(cert_ref__t.extensions__t.san__t.ip_address_in_netw_byte_order__t.len__dtl != 4)
  {
    FLEA_THROW("error with parsed ip address in SAN", FLEA_ERR_FAILED_TEST);
  }*/
  /*if(flea_memcmp_wsize(url__cau8, sizeof(url__cau8) - 1, cert_ref__t.extensions__t.san__t.dns_name_as_ia5str__t.data__pcu8, cert_ref__t.extensions__t.san__t.dns_name_as_ia5str__t.len__dtl))
  {
    //printf("exp len = %u, found len = %u\n", sizeof(url__cau8) - 1, cert_ref__t.extensions__t.san__t.dns_name_as_ia5str__t.len__dtl);
    FLEA_THROW("error with decoded SAN dns name", FLEA_ERR_FAILED_TEST);
  }*/
  if(cert_ref__t.extensions__t.basic_constraints__t.has_path_len__b || cert_ref__t.extensions__t.basic_constraints__t.is_ca__b)
  {
   FLEA_THROW("error decoding empty basic_constraints extensions", FLEA_ERR_FAILED_TEST);
  } 
  if((!cert_ref__t.extensions__t.ext_key_usage__t.is_present__u8) || 
    (cert_ref__t.extensions__t.ext_key_usage__t.purposes__u16 != ((1 << FLEA_ASN1_EKU_BITP_server_auth) | (1 << FLEA_ASN1_EKU_BITP_client_auth))))
  {
   FLEA_THROW("error decoding EKU", FLEA_ERR_FAILED_TEST);

  }
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
      );
}
flea_err_t THR_flea_test_dec_ca_cert()
{
  FLEA_DECL_OBJ(cert_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, test_ca_cert_1, sizeof(test_ca_cert_1)));
  if(cert_ref__t.version__u8 != 3)
  {
    //printf("parsed version number = %u\n", cert_ref__t.version__u8);
    FLEA_THROW("parsed version number is incorrect", FLEA_ERR_FAILED_TEST); 
  }
  if(cert_ref__t.serial_number__t.len__dtl != 1 || cert_ref__t.serial_number__t.data__pcu8[0] != 62)
  {
    //printf("serial len = %u, serial[0] = %u\n", cert_ref__t.serial_number__t.len__dtl, cert_ref__t.serial_number__t.data__pcu8[0]);
    FLEA_THROW("parsed serial number is incorrect", FLEA_ERR_FAILED_TEST); 
  }
  if(cert_ref__t.tbs_sig_algid__t.oid_ref__t.len__dtl != 9 || cert_ref__t.tbs_sig_algid__t.oid_ref__t.data__pcu8[0] != 0x2A)
  {
    FLEA_THROW("parsed tbs sig alg is incorrect", FLEA_ERR_FAILED_TEST); 
  }
  if(cert_ref__t.issuer__t.country__t.len__dtl != 2 || cert_ref__t.issuer__t.country__t.data__pcu8[0] != 'U' || cert_ref__t.issuer__t.country__t.data__pcu8[1] != 'S')
  {
    FLEA_THROW("parsed issuer country is incorrect", FLEA_ERR_FAILED_TEST); 
  }
  if(!FLEA_DER_REF_IS_ABSENT(&cert_ref__t.issuer_unique_id_as_bitstr__t))
  {
    FLEA_THROW("issuer unique id error", FLEA_ERR_FAILED_TEST);
  }
  if(cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.len__dtl != 2 ||  cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.data__pcu8[0] != 0x05 || cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.data__pcu8[1] != 0x00)
  {
    FLEA_THROW("error decoding null params", FLEA_ERR_FAILED_TEST);
  }
  if(!flea_x509_has_key_usages(&cert_ref__t, FLEA_ASN1_KEY_USAGE_MASK_crl_sign | FLEA_ASN1_KEY_USAGE_MASK_key_cert_sign))
  {
    //printf("KU = %04x\n", cert_ref__t.extensions__t.key_usage__t.purposes__u16);
    FLEA_THROW("error positive KU", FLEA_ERR_FAILED_TEST);
  }
  if(flea_x509_has_key_usages(&cert_ref__t, FLEA_ASN1_KEY_USAGE_MASK_data_encipherment))
  {
    FLEA_THROW("error negative KU", FLEA_ERR_FAILED_TEST);
  }
  if(cert_ref__t.extensions__t.subj_key_id__t.len__dtl != 20)
  {
    FLEA_THROW("error len of skid", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
   flea_x509_cert_ref_t__dtor(&cert_ref__t); 
    );
}

/*flea_err_t THR_flea_test_x509_basic()
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_test_dec_ca_cert());
  FLEA_CCALL(THR_flea_test_dec_tls_server_cert_broken());
  FLEA_CCALL(THR_flea_test_dec_tls_server_cert());
  FLEA_THR_FIN_SEC_empty();
}*/
