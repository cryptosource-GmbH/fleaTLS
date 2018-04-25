/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/pubkey.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/x509.h"
#include "internal/common/namespace_asn1.h"
#include "flea/bin_utils.h"
#include "internal/common/x509_key_int.h"
#include "internal/common/oid.h"
#include "flea/mem_read_stream.h"
#include "internal/common/pubkey_int.h"

#ifdef FLEA_HAVE_RSA

flea_err_e THR_get_hash_id_from_x509_id_for_rsa(
  flea_u8_t       cert_id__u8,
  flea_hash_id_e* result__pt
)
{
  FLEA_THR_BEG_FUNC();
  switch(cert_id__u8)
  {
# ifdef FLEA_HAVE_SHA1
      case 5:
        *result__pt = flea_sha1;
        break;
# endif
      case 14:
        *result__pt = flea_sha224;
        break;
      case 11:
        *result__pt = flea_sha256;
        break;
# ifdef FLEA_HAVE_SHA384_512
      case 12:
        *result__pt = flea_sha384;
        break;
      case 13:
        *result__pt = flea_sha512;
        break;
# endif /* ifdef FLEA_HAVE_SHA384_512 */
      default:
        FLEA_THROW("unrecognized hash function", FLEA_ERR_X509_UNRECOG_HASH_FUNCTION);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_public_key_t__create_rsa_key(
  flea_rsa_pubkey_val_t* key__pt,
  const flea_ref_cu8_t*  mod__pcrcu8,
  const flea_ref_cu8_t*  exp__pcrcu8
)
{
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(key__pt->mod_mem__bu8, mod__pcrcu8->len__dtl);
  FLEA_ALLOC_MEM_ARR(key__pt->exp_mem__bu8, exp__pcrcu8->len__dtl);
# endif
  flea_copy_rcu8_use_mem(&key__pt->mod__rcu8, key__pt->mod_mem__bu8, mod__pcrcu8);
  flea_copy_rcu8_use_mem(&key__pt->pub_exp__rcu8, key__pt->exp_mem__bu8, exp__pcrcu8);

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_x509_parse_rsa_public_key(
  const flea_byte_vec_t* public_key_value__pt,
  flea_ref_cu8_t*        modulus__pt,
  flea_ref_cu8_t*        pub_exp__pt
)
{
  flea_rw_stream_t source__t;
  flea_ber_dec_t dec__t;
  flea_mem_read_stream_help_t hlp__t;

  FLEA_THR_BEG_FUNC();
  flea_rw_stream_t__INIT(&source__t);
  flea_ber_dec_t__INIT(&dec__t);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      public_key_value__pt->data__pu8,
      public_key_value__pt->len__dtl,
      &hlp__t
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0, flea_decode_ref));
  /* open sequence */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  /* decode mod */
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, modulus__pt));
  /* decode exp */
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, pub_exp__pt));
  /* close sequence */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&dec__t);
  );
}

flea_err_e THR_flea_public_key_t__ctor_rsa(
  flea_public_key_t*    key__pt,
  const flea_ref_cu8_t* mod__pcrcu8,
  const flea_ref_cu8_t* pub_exp__pcrcu8
)
{
  FLEA_THR_BEG_FUNC();
  key__pt->key_type__t = flea_rsa_key;

  FLEA_CCALL(
    THR_flea_public_key_t__create_rsa_key(
      &key__pt->pubkey_with_params__u.rsa_public_val__t,
      mod__pcrcu8,
      pub_exp__pcrcu8
    )
  );
  key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(
    key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8,
    key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl
    );
  key__pt->primitive_input_size__u16 = (key__pt->key_bit_size__u16 + 7) / 8;

  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_RSA */
