#ifndef _flea_tls_session_mngr__H_
#define _flea_tls_session_mngr__H_

#include "internal/common/default.h"
#include "flea/types.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  // #ifdef FLEA_USE_STACK_BUF
  flea_u8_t session_id__bu8[FLEA_TLS_SESSION_ID_LEN];
  // #else
  // flea_u8_t *session_id__bu8;
  // #endif
  flea_u16_t cipher_suite_id__u16;
  flea_u32_t sequence_number__au32[2];
  flea_u8_t  master_secret__au8[48];
} flea_tls_session_t;

typedef struct
{
#ifdef FLEA_USE_STACK_BUF
  flea_tls_session_t  sessions__bt[FLEA_TLS_MAX_NB_MNGD_SESSIONS ];
  flea_u16_t          use_cnt__bu16[FLEA_TLS_MAX_NB_MNGD_SESSIONS ];
#else
  flea_tls_session_t* sessions__bt;
  flea_u16_t*         use_cnt__bu16;
#endif

  flea_dtl_t          nb_alloc_sessions__dtl;
  flea_u16_t          nb_used_sessions__u16;
} flea_tls_session_mngr_t;

void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr__pt);

#define flea_tls_session_t_INIT(__p) memset(p, sizeof(flea_tls_session_mngr_t), 0)
#define flea_tls_session_t_INIT_VALUE {.session_id__bu8 = 0}

flea_err_t THR_flea_tls_session_mngr_t__ctor(flea_tls_session_mngr_t* session_mngr__pt);
flea_err_t THR_flea_tls_session_mngr_t__get_free_session_slot(
  flea_tls_session_mngr_t* session_mngr__pt,
  flea_tls_session_t**     result__ppt
);
flea_tls_session_t* flea_tls_session_mngr_t__session_cache_lookup(
  flea_tls_session_mngr_t* session_mngr__pt,
  const flea_u8_t*         session_id__pcu8,
  flea_al_u8_t             session_id_len__alu8
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
