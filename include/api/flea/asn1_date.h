#ifndef _flea_asn1_date__H_
#define _flea_asn1_date__H_

#include "internal/common/default.h"
#include "flea/error.h"
#include "flea/types.h"
#include <stdlib.h>
#include "flea/ber_dec.h"
#include "flea/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

flea_err_t THR_flea_asn1_parse_gmt_time(flea_ber_dec_t *dec__t, flea_gmt_time_t *utctime__pt);

flea_err_t THR_flea_asn1_parse_gmt_time_optional(flea_ber_dec_t *dec__t, flea_gmt_time_t *utctime__pt, flea_bool_t *found__pb);

flea_err_t THR_flea_asn1_parse_date(flea_asn1_time_type_t tag__t, const flea_u8_t *value_in, flea_dtl_t value_length, flea_gmt_time_t *value_out);

flea_err_t THR_flea_asn1_parse_generalized_time(const flea_u8_t *value_in, size_t value_length, flea_gmt_time_t *value_out);

flea_err_t THR_flea_asn1_parse_utc_time(const flea_u8_t *value_in, size_t value_length, flea_gmt_time_t *value_out);

int flea_asn1_cmp_utc_time(const flea_gmt_time_t *date1, const flea_gmt_time_t *date2);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
