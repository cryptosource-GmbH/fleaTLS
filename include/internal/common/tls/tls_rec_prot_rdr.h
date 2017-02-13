/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_rec_prot_rdr__H_
#define _flea_tls_rec_prot_rdr__H_


#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_tls_rec_prot_t* rec_prot__pt;
  flea_u8_t            record_type__u8;
} flea_tls_rec_prot_rdr_hlp_t;

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
