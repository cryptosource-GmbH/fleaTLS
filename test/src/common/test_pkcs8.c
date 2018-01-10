/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/privkey.h"
#include "flea/pkcs8.h"
#include "flea/pk_signer.h"
#include "internal/common/math/mpi.h"
#include  "flea/rsa.h"
#include "self_test.h"
#include "flea/alloc.h"
#include <string.h>
#include "test_data_pkcs8.h"

#if defined FLEA_HAVE_ASYM_SIG && defined FLEA_HAVE_SHA1

static flea_err_e THR_flea_test_pkcs8_inner_sign_digest(
  const flea_u8_t*    pkcs8__pcu8,
  flea_al_u16_t       pkcs8_len__alu16,
  flea_hash_id_e      hash_id__t,
  flea_al_u16_t       hash_length__alu16,
  flea_pk_scheme_id_e scheme_id__t
)
{
  FLEA_DECL_OBJ(privkey__t, flea_private_key_t);
  FLEA_DECL_OBJ(pubkey__t, flea_public_key_t);
  const flea_u8_t digest__cau8[255] = {0};
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(sig_vec__t, FLEA_ASYM_MAX_ENCODED_SIG_LEN);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&privkey__t, pkcs8__pcu8, pkcs8_len__alu16));
  FLEA_CCALL(THR_flea_public_key_t__ctor_pkcs8(&pubkey__t, pkcs8__pcu8, pkcs8_len__alu16));
  FLEA_CCALL(
    THR_flea_private_key_t__sign_digest_plain_format(
      &privkey__t,
      scheme_id__t,
      hash_id__t,
      digest__cau8,
      hash_length__alu16,
      &sig_vec__t
    )
  );
  FLEA_CCALL(
    THR_flea_public_key_t__verify_digest_plain_format(
      &pubkey__t,
      scheme_id__t,
      hash_id__t,
      digest__cau8,
      hash_length__alu16,
      sig_vec__t.data__pu8,
      sig_vec__t.len__dtl
    )
  );
  FLEA_THR_FIN_SEC(
    flea_private_key_t__dtor(&privkey__t);
    flea_public_key_t__dtor(&pubkey__t);
  );
} /* THR_flea_test_pkcs8_inner */

static flea_err_e THR_flea_test_pkcs8_inner(
  const flea_u8_t*    pkcs8__pcu8,
  flea_al_u16_t       pkcs8_len__alu16,
  flea_hash_id_e      hash_id__t,
  flea_pk_scheme_id_e scheme_id__t
)
{
  FLEA_DECL_OBJ(privkey__t, flea_private_key_t);
  FLEA_DECL_OBJ(pubkey__t, flea_public_key_t);

  flea_byte_vec_t message_vec__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
    flea_testd_pkcs8_rsa_key_2048_crt__au8,
    sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8)
    );

  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(sig_vec__t, FLEA_ASYM_MAX_ENCODED_SIG_LEN);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&privkey__t, pkcs8__pcu8, pkcs8_len__alu16));
  FLEA_CCALL(THR_flea_public_key_t__ctor_pkcs8(&pubkey__t, pkcs8__pcu8, pkcs8_len__alu16));

  FLEA_CCALL(
    THR_flea_private_key_t__sign_plain_format(
      &privkey__t,
      scheme_id__t,
      hash_id__t,
      &message_vec__t,
      &sig_vec__t
    )
  );

  FLEA_CCALL(
    THR_flea_public_key_t__verify_signature_plain_format(
      &pubkey__t,
      scheme_id__t,
      hash_id__t,
      &message_vec__t,
      &sig_vec__t
    )
  );
  FLEA_THR_FIN_SEC(
    flea_private_key_t__dtor(&privkey__t);
    flea_public_key_t__dtor(&pubkey__t);
  );
} /* THR_flea_test_pkcs8_inner */

flea_err_e THR_flea_test_pkcs8()
{
# ifdef FLEA_HAVE_SHA1
  flea_err_e err__t;
# endif

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_HAVE_SHA1
  err__t = THR_flea_test_pkcs8_inner(
    flea_testd_pkcs8_rsa_key_2048_crt__au8,
    sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8),
    flea_sha256,
    flea_rsa_pkcs1_v1_5_sign
    );

#  if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048
  if(err__t) FLEA_THROW("error in PKCS#8 RSA test", err__t);
#  else
  if(!err__t) FLEA_THROW("no error when expecting one in PKCS#8 RSA test", err__t);
#  endif


#  if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048
  FLEA_CCALL(
    THR_flea_test_pkcs8_inner_sign_digest(
      flea_testd_pkcs8_rsa_key_2048_crt__au8,
      sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8),
      flea_sha1,
      20,
      flea_rsa_pkcs1_v1_5_sign
    )
  );
  if(FLEA_ERR_INV_ARG != THR_flea_test_pkcs8_inner_sign_digest(
      flea_testd_pkcs8_rsa_key_2048_crt__au8,
      sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8),
      flea_sha256,
      20,
      flea_rsa_pkcs1_v1_5_sign
    ))
  {
    FLEA_THROW("did not refuse invalid hash length", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_INV_ARG != THR_flea_test_pkcs8_inner_sign_digest(
      flea_testd_pkcs8_rsa_key_2048_crt__au8,
      sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8),
      flea_sha256,
      128,
      flea_rsa_pkcs1_v1_5_sign
    ))
  {
    FLEA_THROW("did not refuse invalid hash length", FLEA_ERR_FAILED_TEST);
  }

#  endif /* if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 */
  err__t =
    THR_flea_test_pkcs8_inner(
    flea_testd_pkcs8_ecc_key_secp192r1_explicit_params__au8,
    sizeof(flea_testd_pkcs8_ecc_key_secp192r1_explicit_params__au8),
    flea_sha256,
    flea_ecdsa_emsa1
    );
#  if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_ORDER_BIT_SIZE >= 192
  if(err__t) FLEA_THROW("error in PKCS#8 ECC test", err__t);
#  else
  if(!err__t) FLEA_THROW("no error when expecting one in PKCS#8 ECDSA test", err__t);
#  endif

  err__t =
    THR_flea_test_pkcs8_inner(
    flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8,
    sizeof(flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8),
    flea_sha256,
    flea_ecdsa_emsa1
    );
#  if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_ORDER_BIT_SIZE >= 384
  if(err__t) FLEA_THROW("error in PKCS#8 ECC test", err__t);
#  else
  if(!err__t) FLEA_THROW("no error when expecting one in PKCS#8 ECDSA test", err__t);
#  endif
# endif /* ifdef FLEA_HAVE_SHA1 */
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_pkcs8 */

#endif /* if defined FLEA_HAVE_ASYM_SIG && defined FLEA_HAVE_SHA1 */
