/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ec_gfp_dom_par__H_
#define _flea_ec_gfp_dom_par__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/util.h"

//#ifdef FLEA_HAVE_ECC

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * ECC GFP domain parameters type
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

  } flea_ec_gfp_dom_par_ref_t;

#define flea_ec_gfp_dom_par_ref_t__INIT_VALUE { .p__ru8 = {.data__pcu8 = NULL, .len__pdtl = 0} }
#define flea_ec_gfp_dom_par_ref_t__dtor(__p) 



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
  flea_secp192r1, /*NIST FIPS186-3 P-192 */
  flea_secp224r1, /*NIST FIPS186-3 P-224 */
  flea_secp256r1, /*NIST FIPS186-3 P-256 */
  flea_secp384r1, /*NIST FIPS186-3 P-384 */
  flea_secp521r1  /*NIST FIPS186-3 P-521 */
} flea_ec_dom_par_id_t;


extern const flea_ec_dom_par_id_t flea_gl_ec_dom_par_max_id;
/**
 * id type of domain parameter elements.
 */
typedef enum { flea_dp__p = 0, flea_dp__a = 1, flea_dp__b = 2, flea_dp__Gx = 3, flea_dp__Gy = 4, flea_dp__n, flea_dp__h } flea_ec_dom_par_element_id_t;


/**
 * Get the real byte the length of the order n in the domain parameters (in
 * contrast to the encoded length, which might be longer than the real length
 * due to leading zero bytes)
 *
 *  @param enc_dp domain parameters in flea internal format
 *
 *  @return the length of the order
 */
flea_al_u8_t flea_ec_dom_par__get_real_order_byte_len(const flea_u8_t* enc_dp);

/**
 * Get the byte length of an element of the domain parameters specified by their id
 *
 * @param enc_dp domain parameters in flea internal format
 * @param id id of the element to the length of
 */
flea_al_u8_t flea_ec_dom_par__get_elem_len(const flea_u8_t* enc_dp, flea_ec_dom_par_element_id_t id);

/**
 * Get a pointer to the domain parameters in the flea internal format specified
 * by their id.
 *
 * @param dp_id id of the domain parameters

 * @return NULL if the domain parameters with the given id are not found,
 * otherwise a pointer to the domain parameters in the flea internal format
 */
const flea_u8_t* flea_ec_dom_par__get_predefined_dp_ptr(flea_ec_dom_par_id_t dp_id);

/**
 * Get the byte length of the domain parameters in the flea internal format specified
 * by their id.
 *
 * @param dp_id id of the domain parameters

 * @return 0 if the domain parameters with the given id are not found,
 * otherwise the byte length of the domain parameters in the flea internal format
 */
flea_al_u16_t flea_ec_dom_par__get_predefined_dp_len(flea_ec_dom_par_id_t dp_id);


flea_err_t THR_flea_ec_gfp_dom_par_ref_t__set_by_builtin_id(flea_ec_gfp_dom_par_ref_t *dp_to_set__pt, flea_ec_dom_par_id_t id);

flea_u32_t flea_ec_gfp_dom_par_ref_t__get_concat_length(const flea_ec_gfp_dom_par_ref_t *dp__pt);

flea_err_t THR_flea_ec_gfp_dom_par_ref_t__write_to_concat_array(flea_ec_gfp_dom_par_ref_t *output__pt, flea_u8_t *trg_mem__pu8, flea_dtl_t trgt_mem_size__dtl,  const flea_ec_gfp_dom_par_ref_t *input__pt);

#ifdef __cplusplus
}
#endif


//#endif /* #ifdef FLEA_HAVE_ECC */

#endif /* h-guard */
