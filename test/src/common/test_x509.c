/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "internal/common/default.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "test_data_x509_certs.h"
#include "flea/hostn_ver.h"
#include "internal/common/tls/hostn_ver_int.h"

#include <string.h>


flea_err_e THR_flea_test_dec_tls_server_cert_broken()
{
  flea_x509_cert_ref_t cert_ref__t;

  FLEA_THR_BEG_FUNC();
  flea_x509_cert_ref_t__INIT(&cert_ref__t);
  if(!THR_flea_x509_cert_ref_t__ctor(
      &cert_ref__t,
      flea_test_cert_tls_server_broken,
      sizeof(flea_test_cert_tls_server_broken)
    ))
  {
    FLEA_THROW("no excpetion in broken cert", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_test_dec_tls_server_issuer_cert()
{
  flea_x509_cert_ref_t cert_ref__t;

  FLEA_THR_BEG_FUNC();
  flea_x509_cert_ref_t__INIT(&cert_ref__t);
  FLEA_CCALL(
    THR_flea_x509_cert_ref_t__ctor(
      &cert_ref__t,
      flea_test_cert_issuer_of_tls_server_1__cau8,
      sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)
    )
  );

  if(!flea_x509_cert_ref_t__IS_CA(&cert_ref__t))
  {
    FLEA_THROW("error with is ca", FLEA_ERR_FAILED_TEST);
  }

/* ! [parse_cert_path_len] */
  if(!flea_x509_cert_ref_t__HAS_PATH_LEN_LIMIT(&cert_ref__t) ||
    flea_x509_cert_ref_t__GET_PATH_LEN_LIMIT(&cert_ref__t) != 0)
/* ! [parse_cert_path_len] */
  {
    FLEA_THROW("error with path len limit", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
  );
}

flea_err_e THR_flea_test_dec_tls_server_cert()
{
  const char* hostname__cs        = "internal.cryptosource.de";
  const char* wrong_hostname__cs  = "internal.cryptosource.dd";
  const char* wrong_hostname2__cs = "jnternal.cryptosource.de";

  flea_u8_t ipaddr__acu8 []       = {94, 16, 81, 15};
  flea_u8_t wrong_ipaddr__acu8 [] = {94, 16, 81, 14};

  FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(ipaddr_vec__t, ipaddr__acu8, sizeof(ipaddr__acu8));
  FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
    wrong_ipaddr_vec__t,
    wrong_ipaddr__acu8,
    sizeof(wrong_ipaddr__acu8)
  );

  flea_x509_cert_ref_t cert_ref__t;
  FLEA_THR_BEG_FUNC();
  flea_x509_cert_ref_t__INIT(&cert_ref__t);
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, test_cert_tls_server_1, sizeof(test_cert_tls_server_1)));

  FLEA_CCALL(THR_flea_x509__vrfy_tls_srv_id_cstr(hostname__cs, flea_host_dnsname, &cert_ref__t));
  FLEA_CCALL(THR_flea_x509__vrfy_tls_srv_id(&ipaddr_vec__t, flea_host_ipaddr, &cert_ref__t));

  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=
    THR_flea_x509__vrfy_tls_srv_id_cstr(wrong_hostname__cs, flea_host_dnsname, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=
    THR_flea_x509__vrfy_tls_srv_id_cstr(wrong_hostname2__cs, flea_host_dnsname, &cert_ref__t))
  {
    FLEA_THROW("wrong server id accepted", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH !=
    THR_flea_x509__vrfy_tls_srv_id(&wrong_ipaddr_vec__t, flea_host_ipaddr, &cert_ref__t))
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

/* ! [parse_cert_ctor] */
flea_err_e THR_flea_test_dec_ca_cert()
{
  flea_x509_cert_ref_t cert_ref__t;
  flea_ref_cu8_t ref__rcu8;
  flea_bool_t is_ca;
  flea_u32_t path_len_limit;
  const flea_gmt_time_t* time__pt;
  flea_al_u16_t version;

  FLEA_THR_BEG_FUNC();
  flea_x509_cert_ref_t__INIT(&cert_ref__t);
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_ref__t, test_ca_cert_1, sizeof(test_ca_cert_1)));
/* ! [parse_cert_ctor] */
/* ! [parse_cert_version] */
  version = flea_x509_cert_ref_t__GET_CERT_VERSION(&cert_ref__t);
/* ! [parse_cert_version] */
  if(version != 3)
  {
    FLEA_THROW("parsed version number is incorrect", FLEA_ERR_FAILED_TEST);
  }
/* ! [parse_cert_serial] */
  flea_x509_cert_ref_t__GET_SERIAL_NUMBER(&cert_ref__t, &ref__rcu8);
/* ! [parse_cert_serial] */
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
/* ! [parse_cert_time] */
  time__pt = flea_x509_cert_ref_t__get_not_before_ref(&cert_ref__t);
  if(time__pt->year != 2010 || time__pt->month != 1 || time__pt->day != 1 || time__pt->hours != 8 ||
    time__pt->minutes != 30 || time__pt->seconds != 0)
/* ! [parse_cert_time] */
  {
    FLEA_THROW("error with not after", FLEA_ERR_FAILED_TEST);
  }
  time__pt = flea_x509_cert_ref_t__get_not_after_ref(&cert_ref__t);
  if(time__pt->year != 2030 || time__pt->month != 12 || time__pt->day != 31)
  {
    FLEA_THROW("error with not after", FLEA_ERR_FAILED_TEST);
  }
/* ! [parse_cert_issuer_comp] */
  FLEA_CCALL(THR_flea_x509_cert_ref_t__get_issuer_dn_component(&cert_ref__t, flea_dn_cmpnt_country, &ref__rcu8));
/* ! [parse_cert_issuer_comp] */
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
#endif /* ifdef FLEA_X509_CERT_REF_WITH_DETAILS */
  path_len_limit = flea_x509_cert_ref_t__HAS_PATH_LEN_LIMIT(&cert_ref__t);
  if(path_len_limit)
  {
    FLEA_THROW("error with path len limit", FLEA_ERR_FAILED_TEST);
  }
/* ! [parse_cert_is_ca] */
  is_ca = flea_x509_cert_ref_t__IS_CA(&cert_ref__t);
/* ! [parse_cert_is_ca] */
  if(!is_ca)
  {
    FLEA_THROW("error with is ca", FLEA_ERR_FAILED_TEST);
  }
  if(cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.len__dtl != 2 ||
    cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.data__pu8[0] != 0x05 ||
    cert_ref__t.subject_public_key_info__t.algid__t.params_ref_as_tlv__t.data__pu8[1] != 0x00)
  {
    FLEA_THROW("error decoding null params", FLEA_ERR_FAILED_TEST);
  }
/* ! [parse_cert_ku] */
  if(!flea_x509_cert_ref_t__has_key_usages(
      &cert_ref__t,
      (flea_key_usage_e) (flea_ku_crl_sign | flea_ku_key_cert_sign),
      flea_key_usage_explicit
    ))
/* ! [parse_cert_ku] */
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
/* ! [parse_cert_eku] */
  if(!flea_x509_cert_ref_t__has_extended_key_usages(&cert_ref__t, flea_eku_time_stamping, flea_key_usage_implicit))
/* ! [parse_cert_eku] */
  {
    FLEA_THROW("error negative EKU", FLEA_ERR_FAILED_TEST);
  }
  if(flea_x509_cert_ref_t__has_extended_key_usages(
      &cert_ref__t,
      (flea_eku_server_auth | flea_eku_time_stamping),
      flea_key_usage_explicit
    ))
  {
    FLEA_THROW("error negative EKU", FLEA_ERR_FAILED_TEST);
  }

#ifdef FLEA_X509_CERT_REF_WITH_DETAILS
  if(cert_ref__t.extensions__t.subj_key_id__t.len__dtl != 20)
  {
    FLEA_THROW("error len of skid", FLEA_ERR_FAILED_TEST);
  }
#endif /* ifdef FLEA_X509_CERT_REF_WITH_DETAILS */
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&cert_ref__t);
  );
} /* THR_flea_test_dec_ca_cert */
