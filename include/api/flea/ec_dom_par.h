/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ec_gfp_dom_par__H_
#define _flea_ec_gfp_dom_par__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/util.h"

#ifdef FLEA_HAVE_ECC

# ifdef __cplusplus
extern "C" {
# endif

/**
 * ECC GFP domain parameters reference type. The object does only reference the
 * data for the domain parameter components stored in external buffers.
 */
typedef struct
{
  flea_ref_cu8_t p__ru8;
  flea_ref_cu8_t a__ru8;
  flea_ref_cu8_t b__ru8;
  flea_ref_cu8_t gx__ru8;
  flea_ref_cu8_t gy__ru8;
  flea_ref_cu8_t n__ru8;
  flea_ref_cu8_t h__ru8;
} flea_ec_dom_par_ref_t;


/**
 * The domain parameters predefined in flea.
 */
typedef enum
{
  flea_brainpoolP160r1 = 1,
  flea_brainpoolP192r1 = 2,
  flea_brainpoolP224r1 = 3,
  flea_brainpoolP256r1 = 4,
  flea_brainpoolP320r1 = 5,
  flea_brainpoolP384r1 = 6,
  flea_brainpoolP512r1 = 7,

  flea_secp160r1,
  flea_secp160r2,

  /**
   * also known as NIST FIPS186-3 P-192
   */
  flea_secp192r1,

  /**
   * also known as NIST FIPS186-3 P-224
   */
  flea_secp224r1,

  /**
   * also known as NIST FIPS186-3 P-256
   */
  flea_secp256r1,

  /**
   * also known as NIST FIPS186-3 P-384
   */
  flea_secp384r1,

  /**
   *  also known as NIST FIPS186-3 P-521
   */
  flea_secp521r1
} flea_ec_dom_par_id_e;


/**
 * Set a domain parameter reference to one of the builtin domain parameter
 * sets in fleaTLS.
 *
 * @param dp_to_set the domain parameter reference object to set
 * @param id the id of the domain parameters the reference shall point to
 *
 * @return an error code
 */
flea_err_e THR_flea_ec_dom_par_ref_t__set_by_builtin_id(
  flea_ec_dom_par_ref_t* dp_to_set,
  flea_ec_dom_par_id_e   id
);


# ifdef __cplusplus
}
# endif


#endif /* #ifdef FLEA_HAVE_ECC */

#endif /* h-guard */
