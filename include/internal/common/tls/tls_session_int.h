/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_session_int__H_
#define _flea_tls_session_int__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/tls/tls_session_int_fwd.h"
#include "internal/common/tls/tls_const.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_CONST_TLS_SESSION_ID_MAX_LEN 32

struct struct_flea_tls_session_data_t
{
  flea_u8_t  master_secret__au8[FLEA_TLS_MASTER_SECRET_SIZE];
  flea_u16_t cipher_suite_id__u16;
  flea_u8_t  is_valid_session__u8;
};

struct struct_flea_tls_session_entry_t
{
  flea_tls_session_data_t session__t;
  flea_u16_t              use_cnt__u16;
  flea_u8_t               session_id__au8[FLEA_TLS_SESSION_ID_LEN];
};

struct struct_flea_tls_session_mngr_t
{
#ifdef FLEA_USE_STACK_BUF
  flea_tls_session_entry_t  sessions__bt[FLEA_TLS_MAX_NB_MNGD_SESSIONS ];
#else
  flea_tls_session_entry_t* sessions__bt;
#endif

  flea_dtl_t                nb_alloc_sessions__dtl;
  flea_u16_t                nb_used_sessions__u16;
};

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
