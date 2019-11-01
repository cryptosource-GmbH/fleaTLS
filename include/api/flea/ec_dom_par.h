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

#ifndef _flea_ec_gfp_dom_par__H_
# define _flea_ec_gfp_dom_par__H_

# include "internal/common/default.h"
# include "flea/types.h"
# include "flea/util.h"


# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_EC_DOM_PAR_FIRST_ID flea_brainpoolP160r1
# define FLEA_EC_DOM_PAR_LAST_ID  flea_secp521r1

typedef enum
{
  /**
   * a curve unknown to fleaTLS.
   */
  flea_unknown_ec_dp   = 0,
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

# ifdef FLEA_HAVE_ECC

/**
 * ECC domain parameters reference type. The object does only reference the
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
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Determine the ID of a domain parameter reference object.
 *
 * @param dp pointer to the domain parameters
 *
 * @return If the domain * parameters are one of fleaTLS' internal paramaters, then the corresponding ID
 * is returned, otherwise flea_unknown_ec_dp is returned.
 */
flea_ec_dom_par_id_e flea_ec_dom_par_ref_t__determine_known_curve(const flea_ec_dom_par_ref_t* dp);

# endif /* #ifdef FLEA_HAVE_ECC */

# ifdef __cplusplus
}
# endif


#endif /* h-guard */
