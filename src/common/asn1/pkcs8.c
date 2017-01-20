

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "flea/alloc.h"
#include "flea/privkey.h"
#include "flea/array_util.h"
#include "flea/namespace_asn1.h"
#include "flea/pkcs8.h"
#include "flea/bin_utils.h"
#include "internal/common/oid.h"

#ifdef FLEA_HAVE_RSA
static flea_err_t THR_flea_private_key_t__pkcs8_create_rsa_key(flea_private_key_t *privkey_mbn__pt, flea_public_key_t *pubkey_mbn__pt, flea_ber_dec_t *dec__pt)
{
  flea_ref_cu8_t key_components_arcu8 [9];
  flea_al_u8_t i;
  FLEA_THR_BEG_FUNC();
/*RSAPrivateKey ::= SEQUENCE {
    0 |  version           Version,
    1 |  modulus           INTEGER,  -- n
    2 |  publicExponent    INTEGER,  -- e
    3 |  privateExponent   INTEGER,  -- d
    4 |  prime1            INTEGER,  -- p
    5 |  prime2            INTEGER,  -- q
    6 |  exponent1         INTEGER,  -- d mod (p-1)
    7 |  exponent2         INTEGER,  -- d mod (q-1)
    8 |  coefficient       INTEGER,  -- (inverse of q) mod p
    9 |  otherPrimeInfos   OtherPrimeInfos OPTIONAL
   }
   */
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(key_components_arcu8); i++)
  {
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(dec__pt, &key_components_arcu8[i]));
  }
  if(key_components_arcu8[0].len__dtl != 1 || key_components_arcu8[0].data__pcu8[0] != 0)
  {
    FLEA_THROW("wrong RSAPrivateKey version in PKCS#8 decoding", FLEA_ERR_X509_VERSION_ERROR);
  }
  if(privkey_mbn__pt)
  {
    FLEA_CCALL(THR_flea_private_key_t__ctor_rsa_components(
          privkey_mbn__pt, 
          flea__get_BE_int_bit_len(key_components_arcu8[1].data__pcu8, key_components_arcu8[1].len__dtl),
          key_components_arcu8[4].data__pcu8,
          key_components_arcu8[4].len__dtl,
          key_components_arcu8[5].data__pcu8,
          key_components_arcu8[5].len__dtl,
          key_components_arcu8[6].data__pcu8,
          key_components_arcu8[6].len__dtl,
          key_components_arcu8[7].data__pcu8,
          key_components_arcu8[7].len__dtl,
          key_components_arcu8[8].data__pcu8,
          key_components_arcu8[8].len__dtl
          ));
  }
  if(pubkey_mbn__pt)
  {
    FLEA_CCALL(THR_flea_public_key_t__ctor_rsa(pubkey_mbn__pt, &key_components_arcu8[1], &key_components_arcu8[2]));
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_create_private_and_or_public_key_from_pkcs8(flea_private_key_t *privkey_mbn__pt, flea_public_key_t *pubkey_mbn__pt, const flea_u8_t *der_key__pcu8, flea_al_u16_t der_key_len__alu16  )
{

  flea_dtl_t version_len__dtl = 1;
  flea_u8_t version__u8;
  flea_ref_cu8_t ostr__t;
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(cont_source__t, flea_data_source_t);
  flea_data_source_mem_help_t hlp__t;
  flea_data_source_mem_help_t cont_hlp__t;
  flea_x509_algid_ref_t algid_ref__t;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, der_key__pcu8, der_key_len__alu16, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw(&dec__t, FLEA_ASN1_INT, 0, &version__u8, &version_len__dtl));
  if(version_len__dtl != 1)
  {
    FLEA_THROW("PKCS#8 version of invalid length", FLEA_ERR_X509_VERSION_ERROR);
  }
  version__u8 += 1; 
  if(version__u8 > 2)
  {
    FLEA_THROW("invalid PKCS#8 version", FLEA_ERR_X509_VERSION_ERROR);
  }
  FLEA_CCALL(THR_flea_x509__parse_algid_ref(&algid_ref__t, &dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &ostr__t));

  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&cont_source__t, ostr__t.data__pcu8, ostr__t.len__dtl, &cont_hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&cont_dec__t, &cont_source__t, 0));

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&cont_dec__t));
  if(algid_ref__t.oid_ref__t.len__dtl == 9 && !memcmp(algid_ref__t.oid_ref__t.data__pcu8, pkcs1_oid_prefix__cau8, 8) && algid_ref__t.oid_ref__t.data__pcu8[8] == 0x01)
  {
    /* RSA key */
    FLEA_CCALL(THR_flea_private_key_t__pkcs8_create_rsa_key(privkey_mbn__pt, pubkey_mbn__pt, &cont_dec__t));
  } 
  else
  {
    FLEA_THROW("invalid PKCS#8 key type", FLEA_ERR_PKCS8_INVALID_KEY_OID); 
  }
  FLEA_THR_FIN_SEC(
      flea_ber_dec_t__dtor(&dec__t); 
      flea_ber_dec_t__dtor(&cont_dec__t); 
      flea_data_source_t__dtor(&source__t);
      flea_data_source_t__dtor(&cont_source__t);
      );
}

flea_err_t THR_flea_private_key_t__ctor_pkcs8(flea_private_key_t *key__pt, const flea_u8_t *der_key__pcu8, flea_al_u16_t der_key_len__alu16  )
{
  return THR_flea_create_private_and_or_public_key_from_pkcs8(key__pt, NULL, der_key__pcu8, der_key_len__alu16);
}

flea_err_t THR_flea_public_key_t__ctor_pkcs8(flea_public_key_t *key__pt, const flea_u8_t *der_key__pcu8, flea_al_u16_t der_key_len__alu16  )
{
  return THR_flea_create_private_and_or_public_key_from_pkcs8(NULL, key__pt, der_key__pcu8, der_key_len__alu16);
}

#endif /* #ifdef FLEA_HAVE_RSA */
