/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/tls_session_mngr.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include "flea/asn1_date.h"
#include "internal/common/lib_int.h"
#include "internal/common/tls/tls_session_mngr_int.h"


#define FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS  2
#define FLEA_TLS_SESSION_MNGR_PREALLOC_ALLOC_SESSIONS 2


flea_err_e THR_flea_tls_session_mngr_t__ctor(
  flea_tls_session_mngr_t* session_mngr__pt,
  flea_u32_t               session_validity_period_seconds__u32
)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(session_mngr__pt->sessions__bt, FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS);
  session_mngr__pt->nb_alloc_sessions__dtl = FLEA_TLS_SESSION_MNGR_INITIAL_ALLOC_SESSIONS;
#else
  session_mngr__pt->nb_alloc_sessions__dtl = FLEA_TLS_MAX_NB_MNGD_SESSIONS;
#endif
  session_mngr__pt->nb_used_sessions__u16 = 0;
  session_mngr__pt->session_validity_period_seconds__u32 = session_validity_period_seconds__u32;
  if(THR_FLEA_MUTEX_INIT(&session_mngr__pt->m_mutex))
  {
    FLEA_THROW("error initializing mutex", FLEA_ERR_MUTEX_INIT);
  }
  FLEA_THR_FIN_SEC_empty();
}

static void flea_tls_session_mngr_t__incr_use_cnt(
  flea_tls_session_mngr_t*  session_mngr__pt,
  flea_tls_session_entry_t* stored_session__pt
)
{
  if(stored_session__pt->use_cnt__u16 == 0xFFFF)
  {
    flea_al_u16_t i;
    for(i = 0; i < session_mngr__pt->nb_used_sessions__u16; i++)
    {
      session_mngr__pt->sessions__bt[i].use_cnt__u16 /= 2;
    }
  }
  stored_session__pt->use_cnt__u16 += 1;
}

void flea_tls_session_data_t__set_session_as_valid(flea_tls_session_data_t* session__pt)
{
  session__pt->is_valid_session__u8 = 1;
}

void flea_tls_session_data_t__invalidate_session(flea_tls_session_data_t* session__pt)
{
  session__pt->is_valid_session__u8 = 0;
}

flea_bool_t flea_tls_session_data_t__is_valid_session(const flea_tls_session_data_t* session__pt)
{
  return session__pt->is_valid_session__u8;
}

static flea_err_e THR_flea_tls_session_mngr_t__get_free_session_slot(
  flea_tls_session_mngr_t*   session_mngr__pt,
  flea_tls_session_entry_t** result__ppt
)
{
  flea_al_u16_t i;
  flea_tls_session_entry_t* least_frequently_used_session__pt;
  flea_bool_t found__b = FLEA_FALSE;

  FLEA_THR_BEG_FUNC();
  for(i = 0; i < session_mngr__pt->nb_used_sessions__u16; i++)
  {
    if(!flea_tls_session_data_t__is_valid_session(&session_mngr__pt->sessions__bt[i].session__t.session_data__t))
    {
      session_mngr__pt->sessions__bt[i].use_cnt__u16 = 0;
      *result__ppt = &session_mngr__pt->sessions__bt[i];
      found__b     = FLEA_TRUE;
    }
  }
  if(!found__b)
  {
    /* no free session among used session, add one more if capacity allows it */
#ifdef FLEA_USE_HEAP_BUF
    if(session_mngr__pt->nb_alloc_sessions__dtl < FLEA_TLS_MAX_NB_MNGD_SESSIONS)
    {
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
    }
#endif /* ifdef FLEA_USE_HEAP_BUF */

    if(session_mngr__pt->nb_used_sessions__u16 < session_mngr__pt->nb_alloc_sessions__dtl)
    {
      session_mngr__pt->sessions__bt[session_mngr__pt->nb_used_sessions__u16].use_cnt__u16 = 0;
      *result__ppt = &session_mngr__pt->sessions__bt[session_mngr__pt->nb_used_sessions__u16];
      session_mngr__pt->nb_used_sessions__u16 += 1;
      found__b = FLEA_TRUE;
    }
  }
  if(!found__b)
  {
    /* capacity exhausted, need to evict */
    least_frequently_used_session__pt = &session_mngr__pt->sessions__bt[0];
    for(i = 1; i < session_mngr__pt->nb_used_sessions__u16; i++)
    {
      if(session_mngr__pt->sessions__bt[i].use_cnt__u16 < least_frequently_used_session__pt->use_cnt__u16)
      {
        session_mngr__pt->sessions__bt[i].use_cnt__u16 = 0;
        least_frequently_used_session__pt = &session_mngr__pt->sessions__bt[i];
      }
    }
    flea_tls_session_data_t__invalidate_session(&least_frequently_used_session__pt->session__t.session_data__t);

    *result__ppt = least_frequently_used_session__pt;
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_session_mngr_t__get_free_session_slot */

static flea_tls_session_entry_t* flea_tls_session_mngr_t__session_cache_lookup(
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
    if(flea_tls_session_data_t__is_valid_session(&session_mngr__pt->sessions__bt[i].session__t.session_data__t) &&
      !memcmp(session_id__pcu8, session_mngr__pt->sessions__bt[i].session__t.session_id__au8, FLEA_TLS_SESSION_ID_LEN))
    {
      flea_gmt_time_t now__t;
      if(THR_flea_lib__get_gmt_time_now(&now__t))
      {
        return NULL;
      }
      if(-1 == flea_asn1_cmp_utc_time(&session_mngr__pt->sessions__bt[i].session__t.valid_until__t, &now__t))
      {
        flea_tls_session_data_t__invalidate_session(&session_mngr__pt->sessions__bt[i].session__t.session_data__t);
        return NULL;
      }

      return &session_mngr__pt->sessions__bt[i];
    }
  }
  return NULL;
}

flea_err_e THR_flea_tls_session_mngr_t__invalidate_session(
  flea_tls_session_mngr_t* session_mngr__pt,
  flea_u8_t*               session_id__pcu8,
  flea_al_u16_t            session_id_len__alu8
)
{
  flea_tls_session_entry_t* entry__pt;

  FLEA_THR_BEG_FUNC();
  if(THR_FLEA_MUTEX_LOCK(&session_mngr__pt->m_mutex))
  {
    FLEA_THROW("error acquiring mutex", FLEA_ERR_MUTEX_LOCK);
  }
  entry__pt = flea_tls_session_mngr_t__session_cache_lookup(session_mngr__pt, session_id__pcu8, session_id_len__alu8);
  if(entry__pt)
  {
    entry__pt->session__t.session_data__t.is_valid_session__u8 = 0;
  }
  FLEA_THR_FIN_SEC(
    if(THR_FLEA_MUTEX_UNLOCK(&session_mngr__pt->m_mutex))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
}

flea_err_e THR_flea_tls_session_mngr_t__store_session(
  flea_tls_session_mngr_t*              session_mngr__pt,
  const flea_tls_session_data_server_t* server_session_data__pt
)
{
  flea_tls_session_entry_t* stored_session__pt;

  FLEA_THR_BEG_FUNC();

  if(THR_FLEA_MUTEX_LOCK(&session_mngr__pt->m_mutex))
  {
    FLEA_THROW("error acquiring mutex", FLEA_ERR_MUTEX_LOCK);
  }
  stored_session__pt = flea_tls_session_mngr_t__session_cache_lookup(
    session_mngr__pt,
    server_session_data__pt->session_id__au8,
    FLEA_TLS_SESSION_ID_LEN
    );
  if(stored_session__pt)
  {
    FLEA_THR_RETURN();
  }

  FLEA_CCALL(
    THR_flea_tls_session_mngr_t__get_free_session_slot(
      session_mngr__pt,
      &stored_session__pt
    )
  );


  memcpy(&stored_session__pt->session__t, server_session_data__pt, sizeof(*server_session_data__pt));
  stored_session__pt->use_cnt__u16 = 1;
  flea_tls_session_data_t__set_session_as_valid(&stored_session__pt->session__t.session_data__t);

  FLEA_THR_FIN_SEC(
    if(THR_FLEA_MUTEX_UNLOCK(&session_mngr__pt->m_mutex))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
} /* THR_flea_tls_session_mngr_t__store_session */

flea_err_e THR_flea_tls_session_mngr_t__load_session(
  flea_tls_session_mngr_t*        session_mngr__pt,
  const flea_u8_t*                session_id__pcu8,
  flea_al_u8_t                    session_id_len__alu8,
  flea_tls_session_data_server_t* result__pt,
  flea_bool_t*                    load_successful__pb
)
{
  flea_tls_session_entry_t* stored_session__pt;

  FLEA_THR_BEG_FUNC();
  if(THR_FLEA_MUTEX_LOCK(&session_mngr__pt->m_mutex))
  {
    FLEA_THROW("error acquiring mutex", FLEA_ERR_MUTEX_LOCK);
  }
  stored_session__pt = flea_tls_session_mngr_t__session_cache_lookup(
    session_mngr__pt,
    session_id__pcu8,
    session_id_len__alu8
    );
  if(!stored_session__pt)
  {
    *load_successful__pb = FLEA_FALSE;
  }
  else
  {
    *load_successful__pb = FLEA_TRUE;
    flea_tls_session_mngr_t__incr_use_cnt(session_mngr__pt, stored_session__pt);
    memcpy(result__pt, &stored_session__pt->session__t, sizeof(*result__pt));
  }


  FLEA_THR_FIN_SEC(

    if(THR_FLEA_MUTEX_UNLOCK(&session_mngr__pt->m_mutex))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  );
} /* THR_flea_tls_session_mngr_t__load_session */

void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr__pt)
{
#ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(session_mngr__pt->sessions__bt);
#endif
  FLEA_MUTEX_DESTR(&session_mngr__pt->m_mutex);
}
