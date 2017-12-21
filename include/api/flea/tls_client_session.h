/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_client_session__H_
#define _flea_tls_client_session__H_

#ifdef __cplusplus
extern "C" {
#endif

#include "flea/types.h"
#include "flea/byte_vec.h"
#include "internal/common/tls/tls_session_mngr_int.h"

/**
 * Type to hold information of a TLS session for a TLS client. When
 * constructed, this object can be in two states: Directly after creation, it
 * does not hold a valid session. It can receive a valid session either by
 * calling THR_flea_tls_client_session_t_deserialize() on a constructed client
 * session object or by providing it to flea_tls_client_ctx_t ctor.
 */
typedef struct
{
  flea_tls_session_data_t session__t;
  flea_u8_t               session_id__au8[FLEA_CONST_TLS_SESSION_ID_MAX_LEN];
  flea_u8_t               for_resumption__u8;
  flea_u8_t               session_id_len__u8;
} flea_tls_client_session_t;

/**
 * Initialize a client session object.
 *
 * @param client_session pointer to the client session object to initialize.
 */
#define flea_tls_client_session_t__INIT(client_session)

/**
 * Destroy a client session object.
 *
 * @param client_session pointer to the client session object to destroy.
 *
 */
#define flea_tls_client_session_t__dtor(client_session)

/**
 * Determine whether this object holds a valid TLS session.
 *
 * @param client_session pointer to the client session object query.
 *
 * @return FLEA_TRUE if the object holds a valid session, FLEA_FALSE otherwise
 */
flea_bool_e flea_tls_client_session_t__has_valid_session(const flea_tls_client_session_t* client_session);

/**
 * Construct a client session object.
 *
 * @param client_session pointer to the client session object to construct.
 */
void flea_tls_client_session_t__ctor(flea_tls_client_session_t* client_session);


/**
 * Set a new valid session from a serialized session in the client session
 * object.
 *
 * @param client_session pointer to the client session object.
 * @param enc the serialized session
 * @param enc_len the lenth of the serialized session
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_client_session_t__deserialize(
  flea_tls_client_session_t* client_session,
  const flea_u8_t*           enc,
  flea_al_u16_t              enc_len
);

/**
 * Serialize the session held by the client session object. If no valid session
 * is held by the object, the function aborts with an error.
 *
 * @param client_session pointer to the client session object.
 * @param result pointer to the byte vector which receives the serialized
 * session.
 *
 * @return an error code
 */
flea_err_e THR_flea_tls_client_session_t__serialize(
  const flea_tls_client_session_t* client_session,
  flea_byte_vec_t*                 result
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
