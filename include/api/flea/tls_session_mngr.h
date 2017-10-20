#ifndef _flea_tls_session_mngr__H_
#define _flea_tls_session_mngr__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/tls/tls_rec_prot_fwd.h"
// #include "internal/common/tls/tls_int.h"
#include "internal/common/tls/tls_session_int.h"

#ifdef __cplusplus
extern "C" {
#endif


// TODO: SPLIT STANDALONE SESSION (FOR CLIENT)  AND MNGR (FOR SERVER)


typedef struct
{
  flea_tls_session_data_t session__t;
  flea_u16_t              use_cnt__u16;
  flea_u8_t               session_id__au8[FLEA_TLS_SESSION_ID_LEN];
} flea_tls_session_entry_t;

typedef struct
{
#ifdef FLEA_USE_STACK_BUF
  flea_tls_session_entry_t  sessions__bt[FLEA_TLS_MAX_NB_MNGD_SESSIONS ];
#else
  flea_tls_session_entry_t* sessions__bt;
#endif

  flea_dtl_t                nb_alloc_sessions__dtl;
  flea_u16_t                nb_used_sessions__u16;
} flea_tls_session_mngr_t;


void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr__pt);

#ifdef FLEA_USE_HEAP_BUF
# define flea_tls_session_mngr_t__INIT(__p) memset(__p, 0, sizeof(flea_tls_session_mngr_t))
# define flea_tls_session_mngr_t__INIT_VALUE {.sessions__bt = 0, .nb_alloc_sessions__dtl = 0, .nb_used_sessions__u16 = 0}
#else
# define flea_tls_session_mngr_t__INIT(__p)
////# define flea_tls_session_mngr_t__INIT_VALUE {.sessions__bt[0] = .nb_alloc_sessions__dtl = 0, .nb_used_sessions__u16 = 0}
#endif

void flea_tls_session_data_t__export_seq(
  flea_tls_session_data_t const* session__pt,
  flea_tls_stream_dir_e          dir,
  flea_u32_t                     result__pu32[2]
);
void flea_tls_session_data_t__set_seqs(
  flea_tls_session_data_t* session_data__pt,
  flea_u32_t               rd_seqs[2],
  flea_u32_t               wr_seqs[2]
);
flea_bool_t flea_tls_session_data_t__is_valid_session(const flea_tls_session_data_t* session__pt);
flea_err_t THR_flea_tls_session_mngr_t__ctor(flea_tls_session_mngr_t* session_mngr__pt);
flea_err_t THR_flea_tls_session_mngr_t__get_free_session_slot(
  flea_tls_session_mngr_t*   session_mngr__pt,
  flea_tls_session_entry_t** result__ppt
);
flea_tls_session_entry_t* flea_tls_session_mngr_t__session_cache_lookup(
  flea_tls_session_mngr_t* session_mngr__pt,
  const flea_u8_t*         session_id__pcu8,
  flea_al_u8_t             session_id_len__alu8
);

void flea_tls_session_data_t__invalidate_session(flea_tls_session_data_t* session__pt);

void flea_tls_session_data_t__set_session_as_valid(flea_tls_session_data_t* session__pt);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
