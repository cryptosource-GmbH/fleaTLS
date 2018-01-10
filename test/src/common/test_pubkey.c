/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/privkey.h"
#include "flea/pk_signer.h"
#include "internal/common/math/mpi.h"
#include  "flea/rsa.h"
#include  "flea/pk_keypair.h"
#include "self_test.h"
#include "flea/alloc.h"
#include <string.h>
#include "test_data_pkcs8.h"

static flea_err_e THR_flea_test_ecc_key_plain_format_encoding_inner(
  flea_ec_dom_par_id_e dp_id__e,
  flea_hash_id_e       hash_id__e
)
{
#ifdef FLEA_USE_STACK_BUF
  const flea_u8_t enc_pubkey__au8[FLEA_ECC_MAX_ENCODED_POINT_LEN];
  const flea_u8_t enc_privkey__au8[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
  const flea_u8_t sig__au8[2 * FLEA_ECC_MAX_ORDER_BYTE_SIZE];
#endif
  flea_private_key_t privkey__t;
  flea_public_key_t pubkey__t;
  flea_private_key_t privkey2__t;
  flea_public_key_t pubkey2__t;
  flea_byte_vec_t enc_pubkey__t;
  flea_byte_vec_t enc_privkey__t;
  flea_byte_vec_t sig_vec__t;
  flea_byte_vec_t msg_vec__t;
  flea_al_u16_t order_len__alu16;

  flea_ec_gfp_dom_par_ref_t dp_ref__t;
  const flea_u8_t message__acu8[] = {0, 1};
  FLEA_THR_BEG_FUNC();
  flea_public_key_t__INIT(&pubkey__t);
  flea_private_key_t__INIT(&privkey__t);
#ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t__ctor_empty_allocatable(&enc_pubkey__t);
  flea_byte_vec_t__ctor_empty_allocatable(&enc_privkey__t);
  flea_byte_vec_t__ctor_empty_allocatable(&sig_vec__t);
#else
  flea_byte_vec_t__ctor_empty_use_ext_buf(&enc_pubkey__t, enc_pubkey__au8, sizeof(enc_pubkey__au8));
  flea_byte_vec_t__ctor_empty_use_ext_buf(&enc_privkey__t, enc_privkey__au8, sizeof(enc_privkey__au8));
  flea_byte_vec_t__ctor_empty_use_ext_buf(&sig_vec__t, sig__au8, sizeof(sig__au8));
#endif /* ifdef FLEA_USE_HEAP_BUF */
  flea_byte_vec_t__INIT(&msg_vec__t);
  flea_byte_vec_t__reconstruct_as_ref(&msg_vec__t, message__acu8, sizeof(message__acu8));

  FLEA_CCALL(THR_flea_pubkey__generate_ecc_key_pair_by_dp_id(&pubkey__t, &privkey__t, dp_id__e));
  FLEA_CCALL(THR_flea_ec_gfp_dom_par_ref_t__set_by_builtin_id(&dp_ref__t, dp_id__e));

/**
 * sign and verify
 */
  FLEA_CCALL(
    THR_flea_private_key_t__sign_plain_format(
      &privkey__t,
      flea_ecdsa_emsa1,
      hash_id__e,
      &msg_vec__t,
      &sig_vec__t
    )
  );
  FLEA_CCALL(
    THR_flea_public_key_t__verify_signature_plain_format(
      &pubkey__t,
      flea_ecdsa_emsa1,
      hash_id__e,
      &msg_vec__t,
      &sig_vec__t
    )
  );

  FLEA_CCALL(THR_flea_public_key__t__get_encoded_plain(&pubkey__t, &enc_pubkey__t));
  FLEA_CCALL(THR_flea_private_key_t__get_encoded_plain(&privkey__t, &enc_privkey__t));
  order_len__alu16 = flea_byte_vec_t__GET_DATA_LEN(&enc_privkey__t);
  flea_public_key_t__dtor(&pubkey__t);
  flea_private_key_t__dtor(&privkey__t);
  memset(&pubkey__t, 0, sizeof(pubkey__t));
  memset(&privkey__t, 0, sizeof(privkey__t));
  flea_byte_vec_t__dtor(&sig_vec__t);
#ifdef FLEA_USE_HEAP_BUF
  flea_byte_vec_t__ctor_empty_allocatable(&sig_vec__t);
#else
  flea_byte_vec_t__ctor_empty_use_ext_buf(&sig_vec__t, sig__au8, sizeof(sig__au8));
#endif


  FLEA_CCALL(THR_flea_public_key_t__ctor_ecc(&pubkey__t, &enc_pubkey__t, &dp_ref__t));
  FLEA_CCALL(THR_flea_private_key_t__ctor_ecc(&privkey__t, &enc_privkey__t, &dp_ref__t));
  FLEA_CCALL(
    THR_flea_private_key_t__sign_plain_format(
      &privkey__t,
      flea_ecdsa_emsa1,
      hash_id__e,
      &msg_vec__t,
      &sig_vec__t
    )
  );
  FLEA_CCALL(
    THR_flea_public_key_t__verify_signature_plain_format(
      &pubkey__t,
      flea_ecdsa_emsa1,
      hash_id__e,
      &msg_vec__t,
      &sig_vec__t
    )
  );

/**
 * Generate further key pair for testing ECKA/ECDH.
 */
  FLEA_CCALL(THR_flea_pubkey__generate_ecc_key_pair_by_dp_id(&pubkey2__t, &privkey2__t, dp_id__e));

/**
 * Test raw ECKA/ECDH
 */
  FLEA_CCALL(THR_flea_pubkey__compute_ecka(&pubkey__t, &privkey2__t, 0, NULL, 0, (flea_hash_id_e) 0, &enc_privkey__t));
  FLEA_CCALL(THR_flea_pubkey__compute_ecka(&pubkey2__t, &privkey__t, 0, NULL, 0, (flea_hash_id_e) 0, &enc_pubkey__t));

  if(flea_byte_vec_t__cmp(&enc_privkey__t, &enc_pubkey__t))
  {
    FLEA_THROW("error with raw ecka with pubkey api", FLEA_ERR_FAILED_TEST);
  }

/**
 * Test ANSI KDF ECKA/ECDH.
 */
  FLEA_CCALL(
    THR_flea_pubkey__compute_ecka(
      &pubkey__t,
      &privkey2__t,
      order_len__alu16,
      message__acu8,
      sizeof(message__acu8),
      hash_id__e,
      &enc_privkey__t
    )
  );
  FLEA_CCALL(
    THR_flea_pubkey__compute_ecka(
      &pubkey2__t,
      &privkey__t,
      order_len__alu16,
      message__acu8,
      sizeof(message__acu8),
      hash_id__e,
      &enc_pubkey__t
    )
  );

  if(flea_byte_vec_t__cmp(&enc_privkey__t, &enc_pubkey__t))
  {
    FLEA_THROW("error with ANSI KDF ecka with pubkey api", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_private_key_t__dtor(&privkey__t);
    flea_public_key_t__dtor(&pubkey__t);
    flea_private_key_t__dtor(&privkey2__t);
    flea_public_key_t__dtor(&pubkey2__t);
    flea_byte_vec_t__dtor(&enc_pubkey__t);
    flea_byte_vec_t__dtor(&enc_privkey__t);
    flea_byte_vec_t__dtor(&sig_vec__t);
    flea_byte_vec_t__dtor(&msg_vec__t);
  );
} /* THR_flea_test_ecc_key_plain_format_encoding_inner */

flea_err_e THR_flea_test_ecc_key_plain_format_encoding()
{
  FLEA_THR_BEG_FUNC();
#if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_ORDER_BIT_SIZE >= 224 && defined FLEA_HAVE_SHA1
  FLEA_CCALL(THR_flea_test_ecc_key_plain_format_encoding_inner(flea_secp224r1, flea_sha1));
#endif
#if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_ORDER_BIT_SIZE >= 256 && defined FLEA_HAVE_SHA512
  FLEA_CCALL(THR_flea_test_ecc_key_plain_format_encoding_inner(flea_brainpoolP256r1, flea_sha512));
#endif
  FLEA_THR_FIN_SEC_empty();
}
