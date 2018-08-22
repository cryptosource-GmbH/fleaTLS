/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_client_int__H_
# define _flea_tls_client_int__H_

# ifdef __cplusplus
extern "C" {
# endif


flea_err_e THR_flea_tls_ctx_t__client_handle_server_initiated_reneg(
  flea_tls_clt_ctx_t*                   tls_client_ctx__pt,
  const flea_hostn_validation_params_t* hostn_valid_params__pt
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
