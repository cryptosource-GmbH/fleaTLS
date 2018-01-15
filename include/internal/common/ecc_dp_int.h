/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ecc_dp_int__H_
#define _flea_ecc_dp_int__H_

#include "internal/common/default.h"
#include "flea/ec_dom_par.h"

#ifdef FLEA_HAVE_ECC

# ifdef __cplusplus
extern "C" {
# endif

extern const flea_ec_dom_par_id_e flea_gl_ec_dom_par_max_id;

/**
 * id type of domain parameter elements.
 */
typedef enum { flea_dp__p = 0, flea_dp__a = 1, flea_dp__b = 2, flea_dp__Gx = 3, flea_dp__Gy = 4, flea_dp__n,
               flea_dp__h } flea_ec_dom_par_element_id_e;


/**
 * Get the byte length of an element of the domain parameters specified by their id
 *
 * @param enc_dp domain parameters in flea internal format
 * @param id id of the element to the length of
 *
 * @param return the length of the element
 */
flea_al_u8_t flea_ec_dom_par__get_elem_len(
  const flea_u8_t*             enc_dp,
  flea_ec_dom_par_element_id_e id
);

/**
 * Get the byte length of the domain parameters in the flea internal format specified
 * by their id.
 *
 * @param dp_id id of the domain parameters
 *
 * @return 0 if the domain parameters with the given id are not found,
 * otherwise the byte length of the domain parameters in the flea internal format
 */
flea_al_u16_t flea_ec_dom_par__get_predefined_dp_len(flea_ec_dom_par_id_e dp_id);

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


flea_u32_t flea_ec_dom_par_ref_t__get_concat_length(const flea_ec_dom_par_ref_t* dp__pt);

flea_err_e THR_flea_ec_dom_par_ref_t__write_to_concat_array(
  flea_ec_dom_par_ref_t*       output__pt,
  flea_u8_t*                   trg_mem__pu8,
  flea_dtl_t                   trgt_mem_size__dtl,
  const flea_ec_dom_par_ref_t* input__pt
);


const flea_u8_t* flea_ec_dom_par__get_predefined_dp_ptr(flea_ec_dom_par_id_e dp_id);

# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_ECC
#endif /* h-guard */
