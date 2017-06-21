#include "flea/tls_session_mngr.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"

#define FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS  2
#define FLEA_TLS_SESSION_MNGR_PREALLOC_ALLOC_SESSIONS 2
flea_err_t THR_flea_tls_session_mngr_t__ctor(flea_tls_session_mngr_t* session_mngr__pt)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(session_mngr__pt->sessions__bt, FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS);
  FLEA_ALLOC_MEM_ARR(session_mngr__pt->use_cnt__bu16, FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS);
  session_mngr__pt->nb_alloc_sessions__dtl = FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS;
  // memset(session_mngr__pt->use_cnt__bu16, 0,
#else
  session_mngr__pt->nb_alloc_sessions__dtl = FLEA_TLS_MAX_NB_MNGD_SESSIONS;
#endif
  session_mngr__pt->nb_used_sessions__u16 = 0;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_session_mngr_t__get_free_session_slot(
  flea_tls_session_mngr_t* session_mngr__pt,
  flea_tls_session_t**     result__ppt
)
{
  flea_al_u16_t i;
  flea_al_u16_t min_use_cnt__alu16 = 0xFFFF;
  flea_tls_session_t* least_frequently_used_session__pt;

  FLEA_THR_BEG_FUNC();
  for(i = 0; i < session_mngr__pt->nb_used_sessions__u16; i++)
  {
    if(session_mngr__pt->sessions__bt[i].sequence_number__au32[0] == 0 &&
      session_mngr__pt->sessions__bt[i].sequence_number__au32[1] == 0)
    {
      *result__ppt = &session_mngr__pt->sessions__bt[i];
      FLEA_THR_RETURN();
    }
  }
  /* no free session among used session, add one more if capacity allows it */

  FLEA_CCALL(
    THR_flea_alloc__ensure_buffer_capacity(
      (void**) &session_mngr__pt->sessions__bt,
      &session_mngr__pt->nb_alloc_sessions__dtl,
      session_mngr__pt->nb_used_sessions__u16,
      1,
      FLEA_TLS_SESSION_MNGR_PREALLOC_ALLOC_SESSIONS,
      FLEA_TLS_MAX_NB_MNGD_SESSIONS,
      sizeof(session_mngr__pt->sessions__bt[0])
    )
  );
  FLEA_CCALL(
    THR_flea_alloc__ensure_buffer_capacity(
      (void**) &session_mngr__pt->use_cnt__bu16,
      &session_mngr__pt->nb_alloc_sessions__dtl,
      session_mngr__pt->nb_used_sessions__u16,
      1,
      FLEA_TLS_SESSION_MNGR_PREALLOC_ALLOC_SESSIONS,
      FLEA_TLS_MAX_NB_MNGD_SESSIONS,
      sizeof(session_mngr__pt->use_cnt__bu16[0])
    )
  );
  if(session_mngr__pt->nb_used_sessions__u16 < session_mngr__pt->nb_alloc_sessions__dtl)
  {
    *result__ppt = &session_mngr__pt->sessions__bt[session_mngr__pt->nb_used_sessions__u16];
    session_mngr__pt->nb_used_sessions__u16 += 1;
    FLEA_THR_RETURN();
  }
  /* capacity exhausted, need to evict */
  least_frequently_used_session__pt = &session_mngr__pt->sessions__bt[0];
  for(i = 0; i < session_mngr__pt->nb_used_sessions__u16; i++)
  {
    if(session_mngr__pt->use_cnt__bu16[i] < min_use_cnt__alu16)
    {
      min_use_cnt__alu16 = session_mngr__pt->use_cnt__bu16[i];
      least_frequently_used_session__pt = &session_mngr__pt->sessions__bt[i];
    }
  }
  least_frequently_used_session__pt->sequence_number__au32[0] = 0;
  least_frequently_used_session__pt->sequence_number__au32[1] = 0;
  *result__ppt = least_frequently_used_session__pt;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_session_mngr_t__get_free_session_slot */

static void flea_tls_session_mngr_t__incr_use_cnt(
  flea_tls_session_mngr_t* session_mngr__pt,
  flea_al_u16_t            pos
)
{
  if(session_mngr__pt->use_cnt__bu16[pos] == 0xFFFF)
  {
    flea_al_u16_t i;
    for(i = 0; i < session_mngr__pt->nb_used_sessions__u16; i++)
    {
      session_mngr__pt->use_cnt__bu16[i] /= 2;
    }
  }
  session_mngr__pt->use_cnt__bu16[pos] += 1;
}

flea_tls_session_t* flea_tls_session_mngr_t__session_cache_lookup(
  flea_tls_session_mngr_t* session_mngr__pt,
  const flea_u8_t*         session_id__pcu8,
  flea_al_u8_t             session_id_len__alu8
)
{
  flea_al_u16_t i;

  if(session_id_len__alu8 != FLEA_TLS_SESSION_ID_LEN)
  {
    return NULL;
  }
  for(i = 0; i < session_mngr__pt->nb_used_sessions__u16; i++)
  {
    if(session_mngr__pt->sessions__bt[i].sequence_number__au32[0] == 0 &&
      session_mngr__pt->sessions__bt[i].sequence_number__au32[1] == 0 &&
      !memcmp(session_id__pcu8, session_mngr__pt->sessions__bt[i].session_id__bu8, FLEA_TLS_SESSION_ID_LEN))
    {
      flea_tls_session_mngr_t__incr_use_cnt(session_mngr__pt, i);
      return &session_mngr__pt->sessions__bt[i];
    }
  }
  return NULL;
}

void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr__pt)
{
  FLEA_FREE_MEM_CHK_SET_NULL(session_mngr__pt->use_cnt__bu16);
  FLEA_FREE_MEM_CHK_SET_NULL(session_mngr__pt->sessions__bt);
}
