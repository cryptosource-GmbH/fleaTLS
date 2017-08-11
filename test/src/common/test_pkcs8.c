/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/privkey.h"
#include "flea/pkcs8.h"
#include "flea/pk_api.h"
#include "internal/common/math/mpi.h"
#include  "flea/rsa.h"
#include "self_test.h"
#include "flea/alloc.h"
#include <string.h>
#include "test_data_pkcs8.h"

#if defined FLEA_HAVE_ASYM_SIG

static flea_err_t THR_flea_test_pkcs8_inner_sign_digest(
  const flea_u8_t*    pkcs8__pcu8,
  flea_al_u16_t       pkcs8_len__alu16,
  flea_hash_id_t      hash_id__t,
  flea_al_u16_t       hash_length__alu16,
  flea_pk_scheme_id_t scheme_id__t
)
{
  FLEA_DECL_OBJ(privkey__t, flea_private_key_t);
  FLEA_DECL_OBJ(pubkey__t, flea_public_key_t);
  // flea_hash_id_t hash_id__t = flea_sha1;
  const flea_u8_t digest__cau8[255] = {0};
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(sig_vec__t, FLEA_PK_MAX_SIGNATURE_LEN);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&privkey__t, pkcs8__pcu8, pkcs8_len__alu16));
  FLEA_CCALL(THR_flea_public_key_t__ctor_pkcs8(&pubkey__t, pkcs8__pcu8, pkcs8_len__alu16));
  FLEA_CCALL(
    THR_flea_pk_api__sign_digest(
      digest__cau8,
      hash_length__alu16,
      hash_id__t,
      scheme_id__t,
      &privkey__t,
      &sig_vec__t
    )
  );
  FLEA_CCALL(
    THR_flea_public_key_t__verify_digest_raw(
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

static flea_err_t THR_flea_test_pkcs8_inner(
  const flea_u8_t*    pkcs8__pcu8,
  flea_al_u16_t       pkcs8_len__alu16,
  flea_hash_id_t      hash_id__t,
  flea_pk_scheme_id_t scheme_id__t
)
{
  FLEA_DECL_OBJ(privkey__t, flea_private_key_t);
  FLEA_DECL_OBJ(pubkey__t, flea_public_key_t);

  // FLEA_DECL_BUF(sig_buf__b_u8, flea_u8_t, FLEA_PK_MAX_SIGNATURE_LEN);

  /*const flea_ref_cu8_t message__rcu8 = {
   * .data__pcu8 = pkcs8_rsa_key_2048_crt,
   * .len__dtl   = sizeof(pkcs8_rsa_key_2048_crt)
   * };*/
  // FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
  flea_byte_vec_t message_vec__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
    flea_testd_pkcs8_rsa_key_2048_crt__au8,
    sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8)
    );

  /*flea_ref_u8_t signature__ru8;
   * flea_ref_cu8_t signature__rcu8;*/
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(sig_vec__t, FLEA_PK_MAX_SIGNATURE_LEN);
  FLEA_THR_BEG_FUNC();
  // FLEA_ALLOC_BUF(sig_buf__b_u8, FLEA_PK_MAX_SIGNATURE_LEN);

  /*signature__ru8.data__pcu8 = sig_buf__b_u8;
   * signature__ru8.len__dtl   = FLEA_PK_MAX_SIGNATURE_LEN;*/
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&privkey__t, pkcs8__pcu8, pkcs8_len__alu16));
  FLEA_CCALL(THR_flea_public_key_t__ctor_pkcs8(&pubkey__t, pkcs8__pcu8, pkcs8_len__alu16));

  // FLEA_CCALL(THR_flea_pk_api__sign(&message__rcu8, &signature__ru8, &privkey__t, scheme_id__t, hash_id__t));
  FLEA_CCALL(THR_flea_private_key_t__sign(&privkey__t, scheme_id__t, hash_id__t, &message_vec__t, &sig_vec__t));

  /*signature__rcu8.data__pcu8 = signature__ru8.data__pcu8;
  * signature__rcu8.len__dtl   = signature__ru8.len__dtl;*/
  // FLEA_CCALL(THR_flea_pk_api__verify_signature(&message__rcu8, &signature__rcu8, &pubkey__t, scheme_id__t, hash_id__t));
  FLEA_CCALL(
    THR_flea_public_key_t__verify_signature_raw(
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

flea_err_t THR_flea_test_pkcs8()
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();
  err__t = THR_flea_test_pkcs8_inner(
    flea_testd_pkcs8_rsa_key_2048_crt__au8,
    sizeof(flea_testd_pkcs8_rsa_key_2048_crt__au8),
    flea_sha256,
    flea_rsa_pkcs1_v1_5_sign
    );

# if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048
  if(err__t) FLEA_THROW("error in PKCS#8 RSA test", err__t);
# else
  if(!err__t) FLEA_THROW("no error when expecting one in PKCS#8 RSA test", err__t);
# endif


# if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048
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

# endif /* if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 */
  err__t =
    THR_flea_test_pkcs8_inner(
    flea_testd_pkcs8_ecc_key_secp192r1_explicit_params__au8,
    sizeof(flea_testd_pkcs8_ecc_key_secp192r1_explicit_params__au8),
    flea_sha256,
    flea_ecdsa_emsa1
    );
# if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_ORDER_BIT_SIZE >= 192
  if(err__t) FLEA_THROW("error in PKCS#8 ECC test", err__t);
# else
  if(!err__t) FLEA_THROW("no error when expecting one in PKCS#8 ECDSA test", err__t);
# endif

  err__t =
    THR_flea_test_pkcs8_inner(
    flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8,
    sizeof(flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8),
    flea_sha256,
    flea_ecdsa_emsa1
    );
# if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_ORDER_BIT_SIZE >= 384
  if(err__t) FLEA_THROW("error in PKCS#8 ECC test", err__t);
# else
  if(!err__t) FLEA_THROW("no error when expecting one in PKCS#8 ECDSA test", err__t);
# endif
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_pkcs8 */

#endif /* #if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 */
