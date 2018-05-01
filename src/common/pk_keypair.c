/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/ec_key_gen.h"
#include "flea/pk_keypair.h"

#ifdef FLEA_HAVE_ECC

flea_err_e THR_flea_pubkey__by_dp_id_gen_ecc_key_pair(
  flea_pubkey_t*       pub_key__pt,
  flea_privkey_t*      priv_key__pt,
  flea_ec_dom_par_id_e id__e
)
{
  flea_ec_dom_par_ref_t ref__t;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ec_dom_par_ref_t__set_by_builtin_id(&ref__t, id__e));
  FLEA_CCALL(
    THR_flea_pubkey__generate_ecc_key_pair_by_dp(
      pub_key__pt,
      priv_key__pt,
      &ref__t
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_pubkey__generate_ecc_key_pair_by_dp(
  flea_pubkey_t*               pub_key__pt,
  flea_privkey_t*              priv_key__pt,
  const flea_ec_dom_par_ref_t* dp__pt
)
{
  FLEA_DECL_BUF(pub_key__bu8, flea_u8_t, FLEA_PK_MAX_INTERNAL_FORMAT_PUBKEY_LEN);
  FLEA_DECL_BUF(priv_key__bu8, flea_u8_t, FLEA_ECC_MAX_ENCODED_POINT_LEN);

  flea_byte_vec_t scalar_vec__t   = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_byte_vec_t pubpoint_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;

  flea_al_u8_t priv_key_len__alu8 = dp__pt->n__ru8.len__dtl;
  flea_al_u8_t pub_key_len__alu8  = 1 + 2 * dp__pt->p__ru8.len__dtl;
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(pub_key__bu8, pub_key_len__alu8);
  FLEA_ALLOC_BUF(priv_key__bu8, priv_key_len__alu8);
  FLEA_CCALL(
    THR_flea_generate_ecc_key(
      pub_key__bu8,
      &pub_key_len__alu8,
      priv_key__bu8,
      &priv_key_len__alu8,
      dp__pt
    )
  );
  flea_byte_vec_t__set_as_ref(&pubpoint_vec__t, pub_key__bu8, pub_key_len__alu8);
  flea_byte_vec_t__set_as_ref(&scalar_vec__t, priv_key__bu8, priv_key_len__alu8);

  FLEA_CCALL(
    THR_flea_privkey_t__ctor_ecc(
      priv_key__pt,
      &scalar_vec__t,
      dp__pt
    )
  );
  FLEA_CCALL(
    THR_flea_pubkey_t__ctor_ecc(
      pub_key__pt,
      &pubpoint_vec__t,
      dp__pt
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_key__bu8);
    FLEA_FREE_BUF_FINAL(priv_key__bu8);
  );
} /* THR_flea_pubkey__generate_ecc_key_pair_by_dp */

#endif /* ifdef FLEA_HAVE_ECC */
