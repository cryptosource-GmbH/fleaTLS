/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/tls_session_mngr.h"
#include "internal/common/tls/tls_int.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"
#include "internal/common/tls/tls_cert_path.h"
#include "internal/common/tls/tls_client_int.h"

#include "flea/pubkey.h"
#include "flea/asn1_date.h"
#include "api/flea/cert_path.h"
#include "internal/common/ber_dec.h"
#include "flea/rng.h"
#include "flea/block_cipher.h"
#include "flea/util.h"
#include "flea/cert_store.h"
#include "flea/byte_vec.h"
#include "internal/common/tls/tls_ciph_suite.h"
#include "internal/common/tls/parallel_hash.h"
#include "internal/common/lib_int.h"
#include "flea/ec_key_gen.h"
#include "flea/ecka.h"
#include "flea/tls_client.h"
#include "internal/common/tls/tls_ciph_suite.h"
#include "internal/common/tls/tls_common_ecc.h"

#ifdef FLEA_HAVE_TLS

typedef struct
{
  flea_u8_t error;
  flea_u8_t alert;
} error_alert_pair_t;


static const error_alert_pair_t error_alert_map__act [] = {
  {FLEA_ERR_TIMEOUT_ON_STREAM_READ,             FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC,     FLEA_TLS_ALERT_DESC_BAD_RECORD_MAC     },
  {FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH,            FLEA_TLS_ALERT_DESC_UNEXPECTED_MESSAGE },
  {FLEA_ERR_TLS_INV_ALGO_IN_SERVER_HELLO,       FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CIPHERSUITE, FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_TLS_INV_REC_HDR,                    FLEA_TLS_ALERT_DESC_DECRYPT_ERROR      },
  {FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS,         FLEA_TLS_ALERT_DESC_UNKNOWN_CA         },
  {FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH,        FLEA_TLS_ALERT_DESC_CERTIFICATE_UNKNOWN},
  {FLEA_ERR_X509_VERSION_ERROR,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_DEC_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_UNEXP_TAG,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_EXCSS_LEN,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_EXCSS_NST,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DEC_TRGT_BUF_TOO_SMALL,        FLEA_TLS_ALERT_DESC_INTERNAL_ERROR     },
  {FLEA_ERR_ASN1_DER_CALL_SEQ_ERR,              FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_CST_LEN_LIMIT_EXCEEDED,    FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT,            FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_SAN_DEC_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_NEG_INT,                       FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_EKU_VAL_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_SIG_ALG_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_UNSUPP_ALGO,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_BIT_STR_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_UNRECOG_HASH_FUNCTION,         FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_UNSUPP_ALGO_VARIANT,           FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_INV_ECC_KEY_PARAMS,            FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_INV_ECC_FIELD_TYPE,            FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS,        FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_INV_ECC_POINT_ENCODING,        FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_EXCSS_COFACTOR_SIZE,           FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_INV_SIGNATURE,                      FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_CERT_PATH_LEN_CONSTR_EXCEEDED,      FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT,       FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_CERT_REVOKED,                  FLEA_TLS_ALERT_DESC_CERTIFICATE_REVOKED},
  {FLEA_ERR_X509_CERT_REV_STAT_UNDET,           FLEA_TLS_ALERT_DESC_CERTIFICATE_UNKNOWN},
  {FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE,    FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_CERT_NOT_YET_VALID,            FLEA_TLS_ALERT_DESC_CERTIFICATE_EXPIRED},
  {FLEA_ERR_X509_CERT_EXPIRED,                  FLEA_TLS_ALERT_DESC_CERTIFICATE_EXPIRED},
  {FLEA_ERR_TLS_UNSUPP_PROT_VERSION,            FLEA_TLS_ALERT_DESC_PROTOCOL_VERSION   },
  {FLEA_ERR_TLS_PROT_DECODE_ERR,                FLEA_TLS_ALERT_DESC_DECODE_ERROR       },
  {FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG,    FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_FAILED_STREAM_READ,                 FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_FAILED_STREAM_WRITE,                FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_SESSION_CLOSED,                 FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_REC_CLOSE_NOTIFY,               FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_HANDSHK_FAILURE,                FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_TLS_CERT_VER_FAILED,                FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_TLS_EXCSS_REC_LEN,                  FLEA_TLS_ALERT_DESC_RECORD_OVERFLOW    },
  {FLEA_ERR_TLS_NO_SIG_ALG_MATCH,               FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_INV_MAC,                            FLEA_TLS_ALERT_DESC_BAD_RECORD_MAC     },
  {FLEA_ERR_STREAM_EOF,                         FLEA_TLS_ALERT_DESC_DECODE_ERROR       },
  {FLEA_ERR_POINT_NOT_ON_CURVE,                 FLEA_TLS_ALERT_DESC_ILLEGAL_PARAMETER  },
  {FLEA_ERR_X509_CRL_ISSUER_WO_CRL_SIGN,        FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_INV_KEY_SIZE,                       FLEA_TLS_ALERT_DESC_ILLEGAL_PARAMETER  }
};

static flea_bool_t determine_alert_from_error(
  flea_err_e                     err__t,
  flea_tls__alert_description_t* alert_desc__pe,
  flea_bool_t*                   is_reneg_then_not_null__was_accepted_out___pb,
  flea_bool_t                    is_read_app_data__b
)
{
  flea_al_u8_t i;

  if((is_reneg_then_not_null__was_accepted_out___pb && (err__t == FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG)))
  {
    *is_reneg_then_not_null__was_accepted_out___pb = FLEA_FALSE;
    *alert_desc__pe = FLEA_TLS_ALERT_NO_ALERT;
    return FLEA_FALSE;
  }
  else if(is_read_app_data__b && (err__t == FLEA_ERR_TIMEOUT_ON_STREAM_READ))
  {
    /* the read mode is not considered here. instead, the higher functions check
     * wether sufficient data was returned.
     */
    *alert_desc__pe = FLEA_TLS_ALERT_NO_ALERT;
    return FLEA_FALSE;
  }

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(error_alert_map__act); i++)
  {
    if(err__t == error_alert_map__act[i].error)
    {
      *alert_desc__pe = (flea_tls__alert_description_t) error_alert_map__act[i].alert;
      return FLEA_TRUE;
    }
  }
  *alert_desc__pe = FLEA_TLS_ALERT_DESC_INTERNAL_ERROR;
  return FLEA_TRUE;
}

flea_mac_id_e flea_tls__map_hmac_to_hash(flea_hash_id_e hash)
{
  flea_mac_id_e hmac;

  switch(hash)
  {
# ifdef FLEA_HAVE_SHA1
      case flea_sha1:
        hmac = flea_hmac_sha1;
        break;
# endif
      case flea_sha224:
        hmac = flea_hmac_sha224;
        break;
      case flea_sha256:
        hmac = flea_hmac_sha256;
        break;
# ifdef FLEA_HAVE_SHA384_512
      case flea_sha384:
        hmac = flea_hmac_sha384;
        break;
      case flea_sha512:
        hmac = flea_hmac_sha512;
        break;
# endif /* ifdef FLEA_HAVE_SHA384_512 */
      default:
        /* this cannot happen according to callers. dummy value. */
        hmac = flea_hmac_sha256;
        break;
  }
  return hmac;
}

typedef struct
{
  flea_u8_t  type__u8;
  flea_u32_t len__u32;
} handshake_header;

static void flea_tls_ctx_t__set_sec_reneg_flags(
  flea_tls_ctx_t* tls_ctx__pt
)
{
  if(tls_ctx__pt->cfg_flags__e & flea_tls_flag__reneg_mode__allow_insecure_reneg)
  {
    tls_ctx__pt->allow_reneg__u8       = FLEA_TRUE;
    tls_ctx__pt->allow_insec_reneg__u8 = FLEA_TRUE;
  }
  else if(tls_ctx__pt->cfg_flags__e & flea_tls_flag__reneg_mode__allow_secure_reneg)
  {
    tls_ctx__pt->allow_reneg__u8       = FLEA_TRUE;
    tls_ctx__pt->allow_insec_reneg__u8 = FLEA_FALSE;
  }
  else
  {
    tls_ctx__pt->allow_reneg__u8       = FLEA_FALSE;
    tls_ctx__pt->allow_insec_reneg__u8 = FLEA_FALSE;
  }
}

static flea_err_e P_Hash(
  const flea_u8_t* secret,
  flea_u16_t       secret_length,
  const flea_u8_t* label__pcu8,
  flea_al_u8_t     label_len__alu8,
  const flea_u8_t* seed,
  flea_u16_t       seed_length,
  flea_u8_t*       data_out,
  flea_u16_t       res_length,
  flea_mac_id_e    mac_id__e
)
{
  const flea_u16_t mac_out_len__alu8 = flea_mac__get_output_length_by_id(mac_id__e);

  FLEA_DECL_BUF(a__bu8, flea_u8_t, 2 * FLEA_TLS_MAX_MAC_SIZE);
  flea_u8_t* A;
  flea_u8_t* B;
  flea_u8_t* tmp__pu8;
  flea_mac_ctx_t hmac__t = flea_mac_ctx_t__INIT_VALUE;

  // expand to length bytes
  flea_al_u8_t len__alu8 = mac_out_len__alu8;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(a__bu8, 2 * FLEA_TLS_MAX_MAC_SIZE);
  A = a__bu8;
  B = a__bu8 + FLEA_TLS_MAX_MAC_SIZE;
  flea_mac_ctx_t__INIT(&hmac__t);
  FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&hmac__t, mac_id__e, secret, secret_length));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, label__pcu8, label_len__alu8));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, seed, seed_length));
  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&hmac__t, A, &len__alu8));
  flea_mac_ctx_t__dtor(&hmac__t);
  while(res_length)
  {
    flea_al_u8_t to_go__alu16 = FLEA_MIN(res_length, mac_out_len__alu8);
    res_length -= to_go__alu16;
    // A(i) = HMAC_hash(secret, A(i-1))
    flea_mac_ctx_t__INIT(&hmac__t);
    FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&hmac__t, mac_id__e, secret, secret_length));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, A, mac_out_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, label__pcu8, label_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, seed, seed_length));
    len__alu8 = to_go__alu16;
    FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&hmac__t, data_out, &len__alu8));
    data_out += to_go__alu16;
    len__alu8 = mac_out_len__alu8;
    FLEA_CCALL(
      THR_flea_mac__compute_mac(
        mac_id__e,
        secret,
        secret_length,
        A,
        mac_out_len__alu8,
        B,
        &len__alu8
      )
    );
    tmp__pu8 = A;
    A        = B;
    B        = tmp__pu8;
    flea_mac_ctx_t__dtor(&hmac__t);
  }
  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&hmac__t);
    FLEA_FREE_BUF_FINAL_SECRET_ARR(a__bu8, 2 * FLEA_TLS_MAX_MAC_SIZE);
  );
} /* P_Hash */

static flea_err_e flea_tls__prf(
  const flea_u8_t* secret,
  flea_u8_t        secret_length,
  PRFLabel         label,
  const flea_u8_t* seed,
  flea_u16_t       seed_length,
  flea_u16_t       result_length,
  flea_u8_t*       result,
  flea_mac_id_e    mac_id__e
)
{
  const flea_u8_t client_finished[] = {99, 108, 105, 101, 110, 116, 32, 102, 105, 110, 105, 115, 104, 101, 100};
  const flea_u8_t server_finished[] = {115, 101, 114, 118, 101, 114, 32, 102, 105, 110, 105, 115, 104, 101, 100};
  const flea_u8_t master_secret[]   = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
  const flea_u8_t key_expansion[]   = {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};

  const flea_u8_t* label__pcu8;
  flea_al_u8_t label_len__alu8;

  FLEA_THR_BEG_FUNC();

  switch(label)
  {
      case PRF_LABEL_CLIENT_FINISHED:
        label__pcu8     = client_finished;
        label_len__alu8 = sizeof(client_finished);
        break;
      case PRF_LABEL_MASTER_SECRET:
        label__pcu8     = master_secret;
        label_len__alu8 = sizeof(master_secret);
        break;
      case PRF_LABEL_KEY_EXPANSION:
        label__pcu8     = key_expansion,
        label_len__alu8 = sizeof(key_expansion);
        break;
      case PRF_LABEL_SERVER_FINISHED:
        label__pcu8     = server_finished;
        label_len__alu8 = sizeof(server_finished);
        break;
      default:
        FLEA_THROW("Invalid label!", FLEA_ERR_INT_ERR);
  }
  FLEA_CCALL(
    P_Hash(
      secret,
      secret_length,
      label__pcu8,
      label_len__alu8,
      seed,
      seed_length,
      result,
      result_length,
      mac_id__e
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* flea_tls__prf */

static flea_mac_id_e flea_tls__prf_mac_id_from_suite_id(flea_tls_cipher_suite_id_t cs_id__t)
{
# ifdef FLEA_HAVE_SHA384_512

  /** compile time restrictions prevent the instantiation of wrong cipher
   * suites here
   */
  const flea_tls__cipher_suite_t* cs__pt = flea_tls_get_cipher_suite_by_id(cs_id__t);
  if(cs__pt->hash_algorithm == flea_sha384)
  {
    return flea_hmac_sha384;
  }
  else if(cs__pt->hash_algorithm == flea_sha512)
  {
    return flea_hmac_sha512;
  }
# endif /* ifdef FLEA_HAVE_SHA384_512 */
  return flea_hmac_sha256;
}

flea_err_e THR_flea_tls__generate_key_block(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_al_u16_t             selected_cipher_suite__alu16,
  flea_u8_t*                key_block,
  flea_al_u8_t              key_block_len__alu8
)
{
  FLEA_THR_BEG_FUNC();

  flea_swap_mem(
    hs_ctx__pt->client_and_server_random__pt->data__pu8,
    hs_ctx__pt->client_and_server_random__pt->data__pu8 + FLEA_TLS_HELLO_RANDOM_SIZE,
    FLEA_TLS_HELLO_RANDOM_SIZE
  );

  FLEA_CCALL(
    flea_tls__prf(
      hs_ctx__pt->tls_ctx__pt->master_secret__bu8,
      48,
      PRF_LABEL_KEY_EXPANSION,
      hs_ctx__pt->client_and_server_random__pt->data__pu8,
      2 * FLEA_TLS_HELLO_RANDOM_SIZE,
      key_block_len__alu8,
      key_block,
      flea_tls__prf_mac_id_from_suite_id((flea_tls_cipher_suite_id_t) selected_cipher_suite__alu16)
    )
  );
  FLEA_THR_FIN_SEC(
    flea_swap_mem(
      hs_ctx__pt->client_and_server_random__pt->data__pu8,
      hs_ctx__pt->client_and_server_random__pt->data__pu8 + FLEA_TLS_HELLO_RANDOM_SIZE,
      FLEA_TLS_HELLO_RANDOM_SIZE
    );
  );
} /* THR_flea_tls__generate_key_block */

flea_bool_t flea_is_in_ciph_suite_list(
  flea_tls_cipher_suite_id_t        sought_for__e,
  const flea_tls_cipher_suite_id_t* list__pe,
  flea_al_u16_t                     list_len__alu16
)
{
  flea_dtl_t i;

  for(i = 0; i < list_len__alu16; i++)
  {
    if(sought_for__e == list__pe[i])
    {
      return FLEA_TRUE;
    }
  }
  return FLEA_FALSE;
}

flea_err_e THR_flea_tls__handle_tls_error(
  flea_tls_server_ctx_t* server_ctx_mbn__pt,
  flea_tls_client_ctx_t* client_ctx_mbn__pt,
  flea_err_e             err__t,
  flea_bool_t*           is_reneg_then_not_null__was_accepted_out___pb,
  flea_bool_t            is_read_app_data__b
)
{
  FLEA_THR_BEG_FUNC();
  if(err__t)
  {
    flea_tls__alert_description_t alert_desc__e;
    /* determine alert and exception at the same time: */
    flea_bool_t do_send_alert__b = determine_alert_from_error(
      err__t,
      &alert_desc__e,
      is_reneg_then_not_null__was_accepted_out___pb,
      is_read_app_data__b
      );
    if(do_send_alert__b)
    {
      flea_tls_ctx_t* tls_ctx__pt =
        server_ctx_mbn__pt ? &server_ctx_mbn__pt->tls_ctx__t : &client_ctx_mbn__pt->tls_ctx__t;
      if(err__t != FLEA_ERR_TLS_REC_CLOSE_NOTIFY)
      {
        if(client_ctx_mbn__pt && client_ctx_mbn__pt->tls_ctx__t.client_session_mbn__pt)
        {
          flea_tls_session_data_t__invalidate_session(&client_ctx_mbn__pt->tls_ctx__t.client_session_mbn__pt->session__t);
        }
        else if(server_ctx_mbn__pt->session_mngr_mbn__pt)
        {
          FLEA_CCALL(
            THR_flea_tls_session_mngr_t__invalidate_session(
              server_ctx_mbn__pt->session_mngr_mbn__pt,
              server_ctx_mbn__pt->active_session__t.session_id__au8,
              FLEA_TLS_SESSION_ID_LEN
            )
          );
        }
      }
      FLEA_CCALL(THR_flea_tls_rec_prot_t__send_alert_and_throw(&tls_ctx__pt->rec_prot__t, alert_desc__e, err__t));
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__handle_tls_error */

static flea_err_e THR_flea_tls__create_finished_data(
  flea_u8_t*    messages_hash,
  flea_u8_t     messages_hash_len__u8,
  flea_u8_t     master_secret[FLEA_TLS_MASTER_SECRET_SIZE],
  PRFLabel      label,
  flea_u8_t*    data,
  flea_u8_t     data_len,
  flea_mac_id_e mac_id__e
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    flea_tls__prf(
      master_secret,
      FLEA_TLS_MASTER_SECRET_SIZE,
      label,
      messages_hash,
      messages_hash_len__u8,
      data_len,
      data,
      mac_id__e
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__read_finished(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_hash_ctx_t*          hash_ctx
)
{
  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, __FLEA_COMPUTED_MAX_HASH_OUT_LEN + 2 * 12);
  const flea_al_u8_t finished_len__alu8 = FLEA_TLS_VERIFY_DATA_SIZE;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_hash_id_e hash_id__t;
  flea_u8_t hash_len__u8;
  FLEA_THR_BEG_FUNC();

  hash_id__t   = flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__e);
  hash_len__u8 = flea_hash__get_output_length_by_id(hash_id__t);

  FLEA_ALLOC_BUF(messages_hash__bu8, hash_len__u8 + 2 * 12);
  flea_u8_t* finished__pu8     = messages_hash__bu8 + hash_len__u8;
  flea_u8_t* rec_finished__pu8 = messages_hash__bu8 + hash_len__u8 + finished_len__alu8;

  /*
   * use a copy of hash_ctx for send_finished instead of finalizing the original
   */

  // we are working on a copy so we can finalize without copying
  FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx, messages_hash__bu8));

  PRFLabel label;
  if(tls_ctx->connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }
  else
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash__bu8,
      hash_len__u8,
      tls_ctx->master_secret__bu8,
      label,
      finished__pu8,
      finished_len__alu8,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__e)
    )
  );
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      rec_finished__pu8,
      finished_len__alu8
    )
  );
  if(tls_ctx->sec_reneg_flag__u8)
  {
    if(tls_ctx->connection_end == FLEA_TLS_CLIENT && tls_ctx->sec_reneg_flag__u8)
    {
      memcpy(tls_ctx->peer_vfy_data__bu8, rec_finished__pu8, finished_len__alu8);
    }
    else
    {
      memcpy(tls_ctx->own_vfy_data__bu8, rec_finished__pu8, finished_len__alu8);
    }
  }
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("trailing data in finished message", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  if(!flea_sec_mem_equal(rec_finished__pu8, finished__pu8, finished_len__alu8))
  {
    FLEA_THROW("Finished message not verifiable", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(messages_hash__bu8);
  );
} /* THR_flea_tls__read_finished */

flea_err_e THR_flea_tls__read_certificate(
  flea_tls_ctx_t*                    tls_ctx,
  flea_tls_handsh_reader_t*          hs_rdr__pt,
  flea_public_key_t*                 pubkey,
  flea_tls_cert_path_params_t const* cert_path_params__pct
)
{
  flea_u8_t dummy__au8_l3[3];

  FLEA_THR_BEG_FUNC();


  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt),
      dummy__au8_l3,
      sizeof(dummy__au8_l3)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__cert_path_validation(
      tls_ctx,
      hs_rdr__pt,
      tls_ctx->trust_store_mbn_for_server__pt,
      pubkey,
      cert_path_params__pct
    )
  );
  FLEA_THR_FIN_SEC_empty(
  );
} /* THR_flea_tls__read_certificate */

flea_err_e THR_flea_tls__send_certificate(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  const flea_ref_cu8_t*         cert_chain__pt,
  flea_u8_t                     cert_chain_len__u8
)
{
  flea_u32_t hdr_len__u32;
  flea_u32_t cert_list_len__u32;

  FLEA_THR_BEG_FUNC();

  // calculate length for the header
  hdr_len__u32 = 3; // 3 byte for length of certificate list
  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    hdr_len__u32 += 3; // 3 byte for length encoding of each certificate
    hdr_len__u32 += cert_chain__pt[i].len__dtl;
  }

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CERTIFICATE,
      hdr_len__u32
    )
  );

  cert_list_len__u32 = hdr_len__u32 - 3;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_int_be(&tls_ctx->rec_prot__t, p_hash_ctx, cert_list_len__u32, 3));

  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_int_be(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        cert_chain__pt[i].len__dtl,
        3
      )
    );

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        cert_chain__pt[i].data__pcu8,
        cert_chain__pt[i].len__dtl
      )
    );
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_certificate */

flea_err_e THR_flea_tls__send_handshake_message_hdr(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  HandshakeType                 type,
  flea_u32_t                    content_len__u32
)
{
  flea_u8_t enc_for_hash__au8[4];

  FLEA_THR_BEG_FUNC();

  enc_for_hash__au8[0] = type;

  enc_for_hash__au8[1] = content_len__u32 >> 16;
  enc_for_hash__au8[2] = content_len__u32 >> 8;
  enc_for_hash__au8[3] = content_len__u32;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      enc_for_hash__au8,
      sizeof(enc_for_hash__au8)
    )
  );
  if(p_hash_ctx_mbn__pt)
  {
    FLEA_CCALL(
      THR_flea_tls_parallel_hash_ctx_t__update(
        p_hash_ctx_mbn__pt,
        enc_for_hash__au8,
        sizeof(enc_for_hash__au8)
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_handshake_message_hdr */

flea_err_e THR_flea_tls__create_master_secret(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_byte_vec_t*          premaster_secret__pt
)
{
  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  FLEA_CCALL(
    flea_tls__prf(
      premaster_secret__pt->data__pu8,
      premaster_secret__pt->len__dtl,
      PRF_LABEL_MASTER_SECRET,
      hs_ctx__pt->client_and_server_random__pt->data__pu8,
      hs_ctx__pt->client_and_server_random__pt->len__dtl,
      FLEA_TLS_MASTER_SECRET_SIZE,
      tls_ctx__pt->master_secret__bu8,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx__pt->selected_cipher_suite__e)
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__create_master_secret */

flea_err_e THR_flea_tls_ctx_t__construction_helper(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rw_stream__pt
)
{
# ifdef FLEA_HEAP_MODE
  flea_al_u8_t sec_reneg_field_size__alu8 = 12;
# endif
  flea_al_u16_t flags__e = tls_ctx__pt->cfg_flags__e;

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
#  ifdef FLEA_HEAP_MODE
  flea_byte_vec_t__ctor_empty_allocatable(&tls_ctx__pt->peer_ee_cert_data__t);
#  else
  flea_byte_vec_t__ctor_empty_use_ext_buf(
    &tls_ctx__pt->peer_ee_cert_data__t,
    tls_ctx__pt->peer_ee_cert__au8,
    sizeof(tls_ctx__pt->peer_ee_cert__au8)
  );
#  endif /* ifdef FLEA_HEAP_MODE */

# endif /* ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF */
# ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(tls_ctx__pt->master_secret__bu8, FLEA_TLS_MASTER_SECRET_SIZE);
# endif
  flea_tls_ctx_t__set_sec_reneg_flags(tls_ctx__pt);
  tls_ctx__pt->rw_stream__pt = rw_stream__pt;
  /* specify connection end */
  tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e = flea_rev_chk_all;
  if(flags__e & flea_tls_flag__rev_chk_mode__check_only_ee)
  {
    tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e = flea_rev_chk_only_ee;
  }
  if(flags__e & flea_tls_flag__rev_chk_mode__check_none)
  {
    tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e = flea_rev_chk_none;
  }
  /* set TLS version */
  tls_ctx__pt->version.major = 0x03;
  tls_ctx__pt->version.minor = 0x03;
# ifdef FLEA_HEAP_MODE

  sec_reneg_field_size__alu8 = 24;
  FLEA_ALLOC_MEM(tls_ctx__pt->own_vfy_data__bu8, sec_reneg_field_size__alu8);
  /* not used in case of client: */
  tls_ctx__pt->peer_vfy_data__bu8 = tls_ctx__pt->own_vfy_data__bu8 + 12;
# endif /* ifdef FLEA_HEAP_MODE */
  tls_ctx__pt->sec_reneg_flag__u8 = FLEA_FALSE;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__ctor(
      &tls_ctx__pt->rec_prot__t,
      tls_ctx__pt->version.major,
      tls_ctx__pt->version.minor,
      rw_stream__pt
    )
  );
  tls_ctx__pt->selected_cipher_suite__e = (flea_tls_cipher_suite_id_t) 0;


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__construction_helper */

flea_err_e THR_flea_tls__send_handshake_message_content(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  const flea_u8_t*              msg_bytes,
  flea_u32_t                    msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      msg_bytes,
      msg_bytes_len
    )
  );
  if(p_hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__update(p_hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__send_handshake_message_int_be(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  flea_u32_t                    int__u32,
  flea_al_u8_t                  int_byte_width__alu8
)
{
  flea_u8_t enc__au8[4];

  FLEA_THR_BEG_FUNC();
  if(int_byte_width__alu8 > 4)
  {
    int_byte_width__alu8 = 4;
  }
  flea__encode_U32_BE(int__u32, enc__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      rec_prot__pt,
      p_hash_ctx_mbn__pt,
      enc__au8 + (4 - int_byte_width__alu8),
      int_byte_width__alu8
    )
  );

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__send_handshake_message(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  HandshakeType                 type,
  const flea_u8_t*              msg_bytes,
  flea_u32_t                    msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      rec_prot__pt,
      p_hash_ctx_mbn__pt,
      type,
      msg_bytes_len
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      rec_prot__pt,
      p_hash_ctx_mbn__pt,
      msg_bytes,
      msg_bytes_len
    )
  );
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_handshake_message */

flea_err_e THR_flea_tls__send_change_cipher_spec(
  flea_tls_ctx_t* tls_ctx
)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t css_bytes[1] = {1};

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__send_record(
      &tls_ctx->rec_prot__t,
      css_bytes,
      sizeof(css_bytes),
      CONTENT_TYPE_CHANGE_CIPHER_SPEC
    )
  );

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__send_finished(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx

)
{
  FLEA_DECL_BUF(verify_data__bu8, flea_u8_t, FLEA_TLS_VERIFY_DATA_SIZE + FLEA_MAX_HASH_OUT_LEN);
  flea_u8_t* messages_hash__pu8;
  PRFLabel label;
  flea_hash_id_e hash_id__t;
  flea_u8_t hash_len__u8;
  FLEA_THR_BEG_FUNC();

  // compute hash over handshake messages so far
  hash_id__t   = flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__e);
  hash_len__u8 = flea_hash__get_output_length_by_id(hash_id__t);

  FLEA_ALLOC_BUF(verify_data__bu8, FLEA_TLS_VERIFY_DATA_SIZE + hash_len__u8);
  messages_hash__pu8 = verify_data__bu8 + FLEA_TLS_VERIFY_DATA_SIZE;

  FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__final(p_hash_ctx, hash_id__t, FLEA_TRUE, messages_hash__pu8));

  if(tls_ctx->connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }
  else
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash__pu8,
      hash_len__u8,
      tls_ctx->master_secret__bu8,
      label,
      verify_data__bu8,
      FLEA_TLS_VERIFY_DATA_SIZE,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__e)
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_FINISHED,
      verify_data__bu8,
      FLEA_TLS_VERIFY_DATA_SIZE
    )
  );

  if(tls_ctx->sec_reneg_flag__u8)
  {
    if(tls_ctx->connection_end == FLEA_TLS_CLIENT)
    {
      memcpy(tls_ctx->own_vfy_data__bu8, verify_data__bu8, FLEA_TLS_SEC_RENEG_FINISHED_SIZE);
    }
    else
    {
      memcpy(tls_ctx->peer_vfy_data__bu8, verify_data__bu8, FLEA_TLS_SEC_RENEG_FINISHED_SIZE);
    }
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(verify_data__bu8, FLEA_TLS_VERIFY_DATA_SIZE);
  );
} /* THR_flea_tls__send_finished */

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state)
{
  state->expected_messages = 0;
  state->finished         = FLEA_FALSE;
  state->initialized      = FLEA_FALSE;
  state->send_client_cert = FLEA_FALSE;
  state->sent_first_round = FLEA_FALSE;
}

flea_err_e THR_flea_tls_ctx_t__flush_write_app_data(flea_tls_ctx_t* tls_ctx)
{
  return THR_flea_tls_rec_prot_t__write_flush(&tls_ctx->rec_prot__t);
}

static flea_err_e THR_flea_tls_ctx_t__send_app_data_inner(
  flea_tls_ctx_t*  tls_ctx,
  const flea_u8_t* data,
  flea_dtl_t       data_len__dtl
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__send_record(
      &tls_ctx->rec_prot__t,
      data,
      data_len__dtl,
      CONTENT_TYPE_APPLICATION_DATA
    )
  );

  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(&tls_ctx->rec_prot__t));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_ctx_t__send_app_data(
  flea_tls_server_ctx_t* server_ctx_mbn__pt,
  flea_tls_client_ctx_t* client_ctx_mbn__pt,
  const flea_u8_t*       data__pcu8,
  flea_dtl_t             data_len__dtl
)
{
  flea_err_e err__t;

  flea_tls_ctx_t* tls_ctx__pt;

  FLEA_THR_BEG_FUNC();
  tls_ctx__pt = server_ctx_mbn__pt ? &server_ctx_mbn__pt->tls_ctx__t : &client_ctx_mbn__pt->tls_ctx__t;
  err__t      = THR_flea_tls_ctx_t__send_app_data_inner(tls_ctx__pt, data__pcu8, data_len__dtl);

  FLEA_CCALL(THR_flea_tls__handle_tls_error(server_ctx_mbn__pt, client_ctx_mbn__pt, err__t, NULL, FLEA_FALSE));
  FLEA_THR_FIN_SEC_empty();
}

/**
 *
 * @param hostn_valid_params_mbn__pt null for server, not null for client
 */
static flea_err_e THR_flea_tls_ctx_t__read_app_data_inner(
  flea_tls_server_ctx_t*          server_ctx_mbn__pt,
  flea_tls_client_ctx_t*          client_ctx_mbn__pt,
  flea_u8_t*                      data__pu8,
  flea_dtl_t*                     data_len__pdtl,
  flea_stream_read_mode_e         rd_mode__e,
  flea_hostn_validation_params_t* hostn_valid_params_mbn__pt
)
{
  flea_err_e err__t;

  flea_tls_ctx_t* tls_ctx__pt;

  FLEA_THR_BEG_FUNC();

  tls_ctx__pt = server_ctx_mbn__pt ? &server_ctx_mbn__pt->tls_ctx__t : &client_ctx_mbn__pt->tls_ctx__t;

  /*do
  {*/
  err__t = THR_flea_tls_rec_prot_t__read_data(
    &tls_ctx__pt->rec_prot__t,
    CONTENT_TYPE_APPLICATION_DATA,
    data__pu8,
    data_len__pdtl,
    rd_mode__e
    );
  if(err__t == FLEA_EXC_TLS_HS_MSG_DURING_APP_DATA)
  {
    /* assume it's the appropriate ClientHello or HelloRequest in order to
     * initiate a new handshake. a wrong handshake message type will result in
     * an error during the invoked handshake processing. the new record which caused the exception is still
     * held as current record in rec_prot.
     */

    if(tls_ctx__pt->connection_end == FLEA_TLS_SERVER)
    {
# ifdef FLEA_HAVE_TLS_SERVER
      if(tls_ctx__pt->allow_reneg__u8)
      {
        FLEA_CCALL(THR_flea_tls__server_handshake(server_ctx_mbn__pt, FLEA_TRUE));
      }
      else
      {
        flea_tls_rec_prot_t__discard_current_read_record(&tls_ctx__pt->rec_prot__t);
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__send_alert(
            &tls_ctx__pt->rec_prot__t,
            FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION,
            FLEA_TLS_ALERT_LEVEL_WARNING
          )
        );
      }
# else  /* ifdef FLEA_HAVE_TLS_SERVER */
      FLEA_THROW("Invalid State, Server not compiled", FLEA_ERR_INT_ERR);
# endif /* ifdef FLEA_HAVE_TLS_SERVER */
    }
    else   // client
    {
# ifdef FLEA_HAVE_TLS_CLIENT
      if(tls_ctx__pt->allow_reneg__u8)
      {
        FLEA_CCALL(
          THR_flea_tls_ctx_t__client_handle_server_initiated_reneg(
            &client_ctx_mbn__pt->tls_ctx__t,
            hostn_valid_params_mbn__pt
          )
        );
      }
      else
      {
        flea_tls_rec_prot_t__discard_current_read_record(&tls_ctx__pt->rec_prot__t);
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__send_alert(
            &tls_ctx__pt->rec_prot__t,
            FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION,
            FLEA_TLS_ALERT_LEVEL_WARNING
          )
        );
      }
# else  /* ifdef FLEA_HAVE_TLS_CLIENT */
# endif /* ifdef FLEA_HAVE_TLS_CLIENT */
    }
  }
  else if(err__t)
  {
    FLEA_THROW("rethrowing during read app data", err__t);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__read_app_data_inner */

flea_err_e THR_flea_tls_ctx_t__read_app_data(
  flea_tls_server_ctx_t*          server_ctx_mbn__pt,
  flea_tls_client_ctx_t*          client_ctx_mbn__pt,
  flea_u8_t*                      data__pu8,
  flea_dtl_t*                     data_len__pdtl,
  flea_stream_read_mode_e         rd_mode__e,
  flea_hostn_validation_params_t* hostn_valid_params_mbn__pt
)
{
  flea_err_e err__t;
  flea_dtl_t requested__dtl = 0;

  FLEA_THR_BEG_FUNC();

  /* cover read size requirements, since timeouts are swallowed aleady by called
   * function read_app_data_inner */
  if(rd_mode__e == flea_read_full)
  {
    requested__dtl = *data_len__pdtl;
  }
  else if((rd_mode__e == flea_read_blocking) && *data_len__pdtl)
  {
    requested__dtl = 1;
  }
  err__t = THR_flea_tls_ctx_t__read_app_data_inner(
    server_ctx_mbn__pt,
    client_ctx_mbn__pt,
    data__pu8,
    data_len__pdtl,
    rd_mode__e,
    hostn_valid_params_mbn__pt
    );

  FLEA_CCALL(THR_flea_tls__handle_tls_error(server_ctx_mbn__pt, client_ctx_mbn__pt, err__t, NULL, FLEA_TRUE));
  if(requested__dtl && requested__dtl > *data_len__pdtl)
  {
    FLEA_THROW("requested data could not be read from TLS stream", FLEA_ERR_TIMEOUT_ON_STREAM_READ);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_ctx_t__renegotiate(
  flea_tls_server_ctx_t*            server_ctx_mbn__pt,
  flea_tls_client_ctx_t*            client_ctx_mbn__pt,
  flea_bool_t*                      result__pb,
  flea_private_key_t*               private_key__pt,
  const flea_cert_store_t*          trust_store_mbn_for_server__pt,
  const flea_ref_cu8_t*             cert_chain_mbn__pt,  /* may only be null for client */
  flea_al_u8_t                      cert_chain_len__alu8,
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites__pe,
  flea_al_u16_t                     nb_allowed_cipher_suites__alu16,
  const flea_ref_cu8_t*             crl_der__pt,
  flea_al_u16_t                     nb_crls__alu16,
  flea_ec_dom_par_id_e*             allowed_ecc_curves__pe,
  flea_al_u16_t                     nb_allowed_curves__alu16,
  flea_tls_sigalg_e*                allowed_sig_algs__pe,
  flea_al_u16_t                     nb_allowed_sig_algs__alu16,
  flea_hostn_validation_params_t*   hostn_valid_params_mbn__pt
)
{
  flea_err_e err__t;
  flea_tls_ctx_t* tls_ctx__pt;

  FLEA_THR_BEG_FUNC();
  tls_ctx__pt = server_ctx_mbn__pt ? &server_ctx_mbn__pt->tls_ctx__t : &client_ctx_mbn__pt->tls_ctx__t;

  if(!tls_ctx__pt->allow_reneg__u8)
  {
    FLEA_THROW("renegotiation not allowed in this tls connection", FLEA_ERR_TLS_RENEG_NOT_ALLOWED);
  }
  tls_ctx__pt->private_key__pt = private_key__pt;
  tls_ctx__pt->trust_store_mbn_for_server__pt = trust_store_mbn_for_server__pt;
  tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16    = nb_crls__alu16;
  tls_ctx__pt->rev_chk_cfg__t.crl_der__pt     = crl_der__pt;
  tls_ctx__pt->cert_chain_mbn__pt            = cert_chain_mbn__pt;
  tls_ctx__pt->cert_chain_len__u8            = cert_chain_len__alu8;
  tls_ctx__pt->allowed_cipher_suites__pe     = allowed_cipher_suites__pe;
  tls_ctx__pt->nb_allowed_cipher_suites__u16 = nb_allowed_cipher_suites__alu16;
  tls_ctx__pt->allowed_ecc_curves__pe        = allowed_ecc_curves__pe;
  tls_ctx__pt->nb_allowed_curves__u16        = nb_allowed_curves__alu16;
  tls_ctx__pt->allowed_sig_algs__pe          = allowed_sig_algs__pe;
  tls_ctx__pt->nb_allowed_sig_algs__alu16    = nb_allowed_sig_algs__alu16;
  if(tls_ctx__pt->connection_end == FLEA_TLS_CLIENT)
  {
# ifdef FLEA_HAVE_TLS_CLIENT
    err__t =
      THR_flea_tls__client_handshake(
      tls_ctx__pt,
      tls_ctx__pt->client_session_mbn__pt,
      hostn_valid_params_mbn__pt,
      FLEA_TRUE
      );
# else  /* ifdef FLEA_HAVE_TLS_CLIENT */
    FLEA_THROW("Invalid State, Client not compiled", FLEA_ERR_INT_ERR);
# endif /* ifdef FLEA_HAVE_TLS_CLIENT */
  }
  else
  {
# ifdef FLEA_HAVE_TLS_SERVER
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message(
        &tls_ctx__pt->rec_prot__t,
        NULL,
        HANDSHAKE_TYPE_HELLO_REQUEST,
        NULL,
        0
      )
    );
    err__t = THR_flea_tls__server_handshake(server_ctx_mbn__pt, FLEA_TRUE);
# else  /* ifdef FLEA_HAVE_TLS_SERVER */
    FLEA_THROW("Invalid State, Server not compiled", FLEA_ERR_INT_ERR);
# endif /* ifdef FLEA_HAVE_TLS_SERVER */
  }
  *result__pb = FLEA_TRUE; /* might be overriden by handle_tls_error */
  FLEA_CCALL(THR_flea_tls__handle_tls_error(server_ctx_mbn__pt, client_ctx_mbn__pt, err__t, result__pb, FLEA_FALSE));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__renegotiate */

flea_bool_t flea_tls_ctx_t__do_send_sec_reneg_ext(flea_tls_ctx_t* tls_ctx__pt)
{
  if(tls_ctx__pt->connection_end == FLEA_TLS_SERVER)
  {
    if(tls_ctx__pt->sec_reneg_flag__u8 == FLEA_TRUE)
    {
      return FLEA_TRUE;
    }
    return FLEA_FALSE;
  }
  else
  {
    return FLEA_TRUE;
  }
}

flea_al_u16_t flea_tls_ctx_t__compute_extensions_length(flea_tls_ctx_t* tls_ctx__pt)
{
  flea_al_u16_t len__alu16 = 0;

  if(flea_tls_ctx_t__do_send_sec_reneg_ext(tls_ctx__pt))
  {
    flea_al_u8_t reneg_conn_len__alu8 = 0;
    len__alu16 += 5; /* type:2 + data-len:2 + info-len:1 */
    if(tls_ctx__pt->connection_end == FLEA_TLS_CLIENT)
    {
      if(tls_ctx__pt->sec_reneg_flag__u8)
      {
        reneg_conn_len__alu8 += 12;
      }
    }
    else /* server */
    {
      if(tls_ctx__pt->sec_reneg_flag__u8 && flea_tls_rec_prot_t__have_done_initial_handshake(&tls_ctx__pt->rec_prot__t))
      {
        reneg_conn_len__alu8 += 24;
      }
    }
    len__alu16 += reneg_conn_len__alu8;
  }

  // signature algorithms extension
  if(tls_ctx__pt->connection_end == FLEA_TLS_CLIENT)
  {
    len__alu16 += 6 + tls_ctx__pt->nb_allowed_sig_algs__alu16 * 2;
  }

# ifdef FLEA_HAVE_TLS_CS_ECC

  if(tls_ctx__pt->connection_end == FLEA_TLS_CLIENT)
  {
    if(tls_ctx__pt->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES)
    {
      len__alu16 += 6; /* supported curves extension */
      len__alu16 += tls_ctx__pt->nb_allowed_curves__u16 * 2;
    }
    if(tls_ctx__pt->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS)
    {
      len__alu16 += 6; /*  point formats extension */
    }
  }
  /* server: */
  else if(flea_tls__is_cipher_suite_ecc_suite(tls_ctx__pt->selected_cipher_suite__e))
  {
    if(tls_ctx__pt->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS)
    {
      len__alu16 += 6; /*  point formats extension */
    }
  }
# endif /* ifdef FLEA_HAVE_TLS_CS_ECC */
  return len__alu16;
} /* flea_tls_ctx_t__compute_extensions_length */

flea_err_e THR_flea_tls_ctx_t__send_extensions_length(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt
)
{
  flea_u8_t enc_len__au8[2] = {0, 0};
  flea_al_u16_t len__alu16  = 0;

  FLEA_THR_BEG_FUNC();
  len__alu16 = flea_tls_ctx_t__compute_extensions_length(tls_ctx__pt);

  if(len__alu16)
  {
    flea__encode_U16_BE(len__alu16, enc_len__au8);
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx_mbn__pt,
        enc_len__au8,
        sizeof(enc_len__au8)
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_ctx_t__send_reneg_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  const flea_u8_t reneg_ext_type__cau8[] = {0xff, 0x01};
  flea_u8_t len__u8 = 0;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      reneg_ext_type__cau8,
      sizeof(reneg_ext_type__cau8)
    )
  );
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, p_hash_ctx__pt, &len__u8, 1));
  if(tls_ctx__pt->sec_reneg_flag__u8)
  {
    if(tls_ctx__pt->connection_end == FLEA_TLS_CLIENT)
    {
      len__u8 = 12;
    }
    else if(flea_tls_rec_prot_t__have_done_initial_handshake(&tls_ctx__pt->rec_prot__t))
    {
      len__u8 = 24;
    }
  }
  len__u8 += 1;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, p_hash_ctx__pt, &len__u8, 1));
  len__u8 -= 1;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, p_hash_ctx__pt, &len__u8, 1));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      tls_ctx__pt->own_vfy_data__bu8,
      len__u8
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_reneg_ext */

# ifdef FLEA_HAVE_TLS_CS_ECC


# endif /* ifdef FLEA_HAVE_TLS_CS_ECC */

static flea_err_e THR_flea_tls_ctx__parse_reneg_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
)
{
  flea_u8_t len__u8;

  FLEA_DECL_BUF(cmp__bu8, flea_u8_t, 2 * FLEA_TLS_SEC_RENEG_FINISHED_SIZE);
  flea_al_u8_t exp_len__alu8 = FLEA_TLS_SEC_RENEG_FINISHED_SIZE;
  FLEA_THR_BEG_FUNC();
  if(!tls_ctx__pt->sec_reneg_flag__u8)
  {
    exp_len__alu8 = 0;
  }
  if(tls_ctx__pt->connection_end == FLEA_TLS_CLIENT)
  {
    exp_len__alu8 *= 2;
  }
  FLEA_ALLOC_BUF(cmp__bu8, exp_len__alu8);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      rd_strm__pt,
      &len__u8
    )
  );
  if(len__u8 + 1 != ext_len__alu16)
  {
    FLEA_THROW("inconsistent length for reneg info", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  if(len__u8 != exp_len__alu8)
  {
    FLEA_THROW("invalid renegotiation info size", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      rd_strm__pt,
      cmp__bu8,
      exp_len__alu8
    )
  );

  if(!flea_sec_mem_equal(tls_ctx__pt->own_vfy_data__bu8, cmp__bu8, exp_len__alu8))
  {
    FLEA_THROW("invalid renegotiation info content", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

  if(flea_tls_rec_prot_t__have_done_initial_handshake(&tls_ctx__pt->rec_prot__t) && !len__u8)
  {
    FLEA_THROW("empty renegotiation info provided during handshake after the first", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(cmp__bu8);
  );
} /* THR_flea_tls_ctx__parse_reneg_ext */

flea_u8_t flea_tls_map_tls_hash_to_flea_hash__at[6][2] = {
# ifdef FLEA_HAVE_MD5
  {0x01, flea_md5   },
# endif
# ifdef FLEA_HAVE_SHA1
  {0x02, flea_sha1  },
# endif
  {0x03, flea_sha224},
  {0x04, flea_sha256},
# ifdef FLEA_HAVE_SHA384_512
  {0x05, flea_sha384},
  {0x06, flea_sha512}
# endif
};

flea_u8_t flea_tls_map_tls_sig_to_flea_sig__at[2][2] = {
  {0x01, flea_rsa_pkcs1_v1_5_sign},
  {0x03, flea_ecdsa_emsa1_asn1   }
};


flea_err_e THR_flea_tls__map_tls_sig_to_flea_sig(
  flea_u8_t            id__u8,
  flea_pk_scheme_id_e* pk_scheme_id__pt
)
{
  FLEA_THR_BEG_FUNC();

  for(flea_u8_t i = 0; i < FLEA_NB_ARRAY_ENTRIES(flea_tls_map_tls_sig_to_flea_sig__at); i++)
  {
    if(flea_tls_map_tls_sig_to_flea_sig__at[i][0] == id__u8)
    {
      *pk_scheme_id__pt = (flea_pk_scheme_id_e) flea_tls_map_tls_sig_to_flea_sig__at[i][1];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("unsupported signature algorithm", FLEA_ERR_TLS_HANDSHK_FAILURE);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__map_flea_sig_to_tls_sig(
  flea_pk_scheme_id_e pk_scheme_id__t,
  flea_u8_t*          id__pu8
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < FLEA_NB_ARRAY_ENTRIES(flea_tls_map_tls_sig_to_flea_sig__at); i++)
  {
    if(flea_tls_map_tls_sig_to_flea_sig__at[i][1] == pk_scheme_id__t)
    {
      *id__pu8 = flea_tls_map_tls_sig_to_flea_sig__at[i][0];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("signature algorithm has no mapping for tls", FLEA_ERR_INT_ERR);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__map_tls_hash_to_flea_hash(
  flea_u8_t       id__u8,
  flea_hash_id_e* hash_id__pt
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < FLEA_NB_ARRAY_ENTRIES(flea_tls_map_tls_hash_to_flea_hash__at); i++)
  {
    if(flea_tls_map_tls_hash_to_flea_hash__at[i][0] == id__u8)
    {
      *hash_id__pt = (flea_hash_id_e) flea_tls_map_tls_hash_to_flea_hash__at[i][1];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("unsupported hash algorithm", FLEA_ERR_TLS_HANDSHK_FAILURE);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls__map_flea_hash_to_tls_hash(
  flea_hash_id_e hash_id__t,
  flea_u8_t*     id__pu8
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < FLEA_NB_ARRAY_ENTRIES(flea_tls_map_tls_hash_to_flea_hash__at); i++)
  {
    if(flea_tls_map_tls_hash_to_flea_hash__at[i][1] == hash_id__t)
    {
      *id__pu8 = flea_tls_map_tls_hash_to_flea_hash__at[i][0];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("hash algorithm has no mapping for tls", FLEA_ERR_INT_ERR);
  FLEA_THR_FIN_SEC_empty();
}

flea_pk_scheme_id_e flea_tls__get_sig_alg_from_key_type(
  flea_pk_key_type_e key_type__t
)
{
  if(key_type__t == flea_ecc_key)
  {
    return flea_ecdsa_emsa1_asn1;
  }
  else
  {
    return flea_rsa_pkcs1_v1_5_sign;
  }
}

flea_u8_t flea_tls__get_tls_cert_type_from_flea_key_type(flea_pk_key_type_e key_type__t)
{
  if(key_type__t == flea_rsa_key)
  {
    return FLEA_TLS_CERT_TYPE_RSA_SIGN;
  }
  return FLEA_TLS_CERT_TYPE_ECDSA_SIGN;
}

flea_u8_t flea_tls__get_tls_cert_type_from_flea_pk_scheme(flea_pk_scheme_id_e pk_scheme__t)
{
  if(pk_scheme__t == flea_rsa_pkcs1_v1_5_sign)
  {
    return FLEA_TLS_CERT_TYPE_RSA_SIGN;
  }
  return FLEA_TLS_CERT_TYPE_ECDSA_SIGN;
}

// check whether an offered sig/hash algorithm pair matches the certificate.
// Does not check additional constraints
flea_err_e THR_flea_tls__check_sig_alg_compatibility_for_key_type(
  flea_pk_key_type_e  key_type__t,
  flea_pk_scheme_id_e pk_scheme_id__t
)
{
  FLEA_THR_BEG_FUNC();
  if((key_type__t == flea_ecc_key &&
    ((pk_scheme_id__t != flea_ecdsa_emsa1_asn1) && (pk_scheme_id__t != flea_ecdsa_emsa1_concat))) ||
    (key_type__t == flea_rsa_key && pk_scheme_id__t != flea_rsa_pkcs1_v1_5_sign))
  {
    FLEA_THROW("key type and signature algorithm do not match", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_ctx_t__send_sig_alg_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  const flea_u8_t ext__au8[] = {
    0x00, 0x0d
  };
  flea_u8_t curr_sig_alg_enc__au8[2];

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_int_be(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      tls_ctx__pt->nb_allowed_sig_algs__alu16 * 2 + 2,
      2
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_int_be(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      tls_ctx__pt->nb_allowed_sig_algs__alu16 * 2,
      2
    )
  );

  // send supported sig algs
  for(flea_dtl_t i = 0; i < tls_ctx__pt->nb_allowed_sig_algs__alu16; i += 1)
  {
    FLEA_CCALL(
      THR_flea_tls__map_flea_hash_to_tls_hash(
        (flea_hash_id_e) (tls_ctx__pt->allowed_sig_algs__pe[i] >> 8),
        &curr_sig_alg_enc__au8[0]
      )
    );
    FLEA_CCALL(
      THR_flea_tls__map_flea_sig_to_tls_sig(
        (flea_pk_scheme_id_e) (tls_ctx__pt->allowed_sig_algs__pe[i] & 0xFF),
        &curr_sig_alg_enc__au8[1]
      )
    );

    FLEA_CCALL(

      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        curr_sig_alg_enc__au8,
        sizeof(curr_sig_alg_enc__au8)
      )
    );
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_sig_alg_ext */

flea_err_e THR_flea_tls__read_sig_algs_field_and_find_best_match(
  flea_tls_ctx_t*     tls_ctx__pt,
  flea_rw_stream_t*   hs_rd_stream__pt,
  flea_u16_t          sig_algs_len__u16,
  flea_private_key_t* priv_key_mbn__pt
)
{
  flea_al_u16_t hash_alg_pos__alu16 = 0xFFFF;
  flea_hash_id_e hash_id__t;
  flea_pk_scheme_id_e pk_scheme_id__t;
  flea_u8_t curr_sig_alg__au8[2];

  FLEA_THR_BEG_FUNC();

  // find matching algorithm for signature
  while(sig_algs_len__u16)
  {
    sig_algs_len__u16 -= 2;
    flea_al_u16_t i;


    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        hs_rd_stream__pt,
        curr_sig_alg__au8,
        2
      )
    );
    // map sig and hash alg and also check that the sig alg matches our key
    if(THR_flea_tls__map_tls_hash_to_flea_hash(
        curr_sig_alg__au8[0],
        &hash_id__t
      ) || THR_flea_tls__map_tls_sig_to_flea_sig(curr_sig_alg__au8[1], &pk_scheme_id__t))
    {
      continue;
    }
    if(priv_key_mbn__pt &&
      THR_flea_tls__check_sig_alg_compatibility_for_key_type(priv_key_mbn__pt->key_type__t, pk_scheme_id__t))
    {
      continue;
    }

    // if the sig/hash pair is suitable, use it if it's highest priority
    for(i = 0; i < tls_ctx__pt->nb_allowed_sig_algs__alu16; i += 1)
    {
      if(hash_id__t == (flea_hash_id_e) tls_ctx__pt->allowed_sig_algs__pe[i] >> 8)
      {
        if(i / 2 < hash_alg_pos__alu16)
        {
          /* update if it has higher priority */
          hash_alg_pos__alu16 = i / 2;
          tls_ctx__pt->chosen_hash_algorithm__t = hash_id__t;
        }
        break;
      }
    }
  }

  if(hash_alg_pos__alu16 == 0xFFFF)
  {
    FLEA_THROW("Could not agree on signature algorithm", FLEA_ERR_TLS_NO_SIG_ALG_MATCH);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_sig_algs_field_and_find_best_match */

flea_err_e THR_flea_tls_ctx_t__parse_sig_alg_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
)
{
  flea_al_u16_t len__alu16;
  flea_err_e err__t;

  FLEA_THR_BEG_FUNC();
  if(!ext_len__alu16)
  {
    /* RFC 5246 states:
     *    If the client provided a "signature_algorithms" extension, then all
     *    certificates provided by the server MUST be signed by a
     *    hash/signature algorithm pair that appears in that extension.
     * which basically means that aborting is the correct behaviour
     */
    FLEA_THROW("No Signature and Hash algorithms offered by client", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

  FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(rd_strm__pt, &len__alu16, 2));
  if((len__alu16 % 2) || (len__alu16 > ext_len__alu16 - 2))
  {
    FLEA_THROW("invalid signature algorithms extension", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  /* find match of received algorithms and configured algorithms.
   * this function can only be called by the server */
  err__t = THR_flea_tls__read_sig_algs_field_and_find_best_match(
    tls_ctx__pt,
    rd_strm__pt,
    len__alu16,
    tls_ctx__pt->private_key__pt
    );

  if(err__t)
  {
    if(err__t == FLEA_ERR_TLS_NO_SIG_ALG_MATCH)
    {
      // we didn't find a matching signature algorithm so we can't use ECDHE
      // since we can't sign the key.
      tls_ctx__pt->can_use_ecdhe = FLEA_FALSE;
    }
    else
    {
      // rethrow error
      FLEA_THROW("rethrowing error from reading the Signature Algorithms Field", err__t);
    }
  }
  else
  {
    // no error, we found a matching signature algorithm
    tls_ctx__pt->can_use_ecdhe = FLEA_TRUE;
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__parse_sig_alg_ext */

/*static void flea_tls_ctx_t__reset_extension_state(flea_tls_ctx_t* tls_ctx__pt)
 * {
 * tls_ctx__pt->sec_reneg_flag__u8 = FLEA_FALSE;
 * }*/
flea_err_e THR_flea_tls_ctx_t__parse_hello_extensions(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_bool_t*              found_sec_reneg__pb,
  flea_private_key_t*       priv_key_mbn__pt
)
{
  flea_u32_t extensions_len__u32;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_bool_t receive_sig_algs_ext__b = FLEA_FALSE;
  flea_bool_t support_sha1__b         = FLEA_FALSE;
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();

  /**
   * pre-selection which takes effect in case the peer doesn't send the
   * supported curves extension.
   */
  if(tls_ctx__pt->nb_allowed_curves__u16)
  {
    tls_ctx__pt->chosen_ecc_dp_internal_id__u8 = tls_ctx__pt->allowed_ecc_curves__pe[0];
  }
  else
  {
    tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__UNMATCHING;
  }

  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) == 0)
  {
    FLEA_THR_RETURN();
  }

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_int_be(
      hs_rd_stream__pt,
      &extensions_len__u32,
      2
    )
  );
  while(extensions_len__u32)
  {
    flea_u32_t ext_type_be__u32;
    flea_u32_t ext_len__u32;
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_int_be(
        hs_rd_stream__pt,
        &ext_type_be__u32,
        2
      )
    );
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_int_be(
        hs_rd_stream__pt,
        &ext_len__u32,
        2
      )
    );
    extensions_len__u32 -= (((flea_u32_t) 4) + ext_len__u32);

    if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__RENEG_INFO)
    {
      FLEA_CCALL(THR_flea_tls_ctx__parse_reneg_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      *found_sec_reneg__pb = FLEA_TRUE;
    }
    // skip over ext. if received from server (not allowed)
# ifdef FLEA_HAVE_TLS_SERVER
    else if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__SIGNATURE_ALGORITHMS &&
      tls_ctx__pt->connection_end == FLEA_TLS_SERVER)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__parse_sig_alg_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      receive_sig_algs_ext__b = FLEA_TRUE;
    }
# endif /* ifdef FLEA_HAVE_TLS_SERVER */
# ifdef FLEA_HAVE_TLS_CS_ECC
    else if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__POINT_FORMATS)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__parse_point_formats_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS;
    }
    else if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__SUPPORTED_CURVES &&
      tls_ctx__pt->connection_end == FLEA_TLS_SERVER)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__parse_supported_curves_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES;
    }
# endif /* ifdef FLEA_HAVE_TLS_CS_ECC */
    else
    {
      FLEA_CCALL(
        THR_flea_rw_stream_t__skip_read(
          hs_rd_stream__pt,
          ext_len__u32
        )
      );
    }
  }

  // no signature_algorithms ext. received from client
  if(receive_sig_algs_ext__b == FLEA_FALSE && tls_ctx__pt->connection_end == FLEA_TLS_SERVER)
  {
    // we need to set the default signature and hash algorithm because the
    // client does not support any other. This means sha1 + signature scheme
    // of the currently loaded certificate
    for(i = 0; i < tls_ctx__pt->nb_allowed_sig_algs__alu16; i += 1)
    {
      // only check for hash/sig pair which matches our key
      if(priv_key_mbn__pt && THR_flea_tls__check_sig_alg_compatibility_for_key_type(
          priv_key_mbn__pt->key_type__t,
          (flea_pk_scheme_id_e) (tls_ctx__pt->allowed_sig_algs__pe[i] & 0xFF)
        ))
      {
        continue;
      }
# ifdef FLEA_HAVE_SHA1
      if((tls_ctx__pt->allowed_sig_algs__pe[i] >> 8) == flea_sha1)
      {
        support_sha1__b = FLEA_TRUE;
        break;
      }
# endif /* ifdef FLEA_HAVE_SHA1 */
    }
    if(support_sha1__b == FLEA_FALSE)
    {
      tls_ctx__pt->can_use_ecdhe = FLEA_FALSE;
    }
    else
    {
# ifdef FLEA_HAVE_SHA1
      tls_ctx__pt->chosen_hash_algorithm__t = flea_sha1;
# else
      FLEA_THROW("no supported hash algorithm found", FLEA_ERR_TLS_HANDSHK_FAILURE);
# endif
      tls_ctx__pt->can_use_ecdhe = FLEA_TRUE;
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__client_parse_extensions */

# ifdef FLEA_HAVE_TLS_CS_ECC


# endif /* ifdef FLEA_HAVE_TLS_CS_ECC */

# ifdef FLEA_HAVE_TLS_CS_ECDHE
flea_err_e THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret(
  flea_tls_ctx_t*     tls_ctx__pt,
  flea_rw_stream_t*   hs_rd_stream__pt,
  flea_byte_vec_t*    premaster_secret__pt,
  flea_private_key_t* priv_key__pt,
  flea_public_key_t*  peer_pubkey__pt
)
{
  flea_u8_t peer_enc_pubpoint_len__u8;

  FLEA_DECL_BUF(peer_enc_pubpoint__bu8, flea_u8_t, FLEA_ECC_MAX_ENCODED_POINT_LEN);
  flea_byte_vec_t peer_enc_pubpoint_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_ec_dom_par_ref_t ecc_dp__t;
  flea_al_u8_t result_len__alu8;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      hs_rd_stream__pt,
      &peer_enc_pubpoint_len__u8
    )
  );
  if(peer_enc_pubpoint_len__u8 > FLEA_ECC_MAX_ENCODED_POINT_LEN)
  {
    FLEA_THROW("peer pub point too large", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_ALLOC_BUF(peer_enc_pubpoint__bu8, peer_enc_pubpoint_len__u8);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      peer_enc_pubpoint__bu8,
      peer_enc_pubpoint_len__u8
    )
  );

  flea_byte_vec_t__set_as_ref(&peer_enc_pubpoint_vec__t, peer_enc_pubpoint__bu8, peer_enc_pubpoint_len__u8);
  FLEA_CCALL(
    THR_flea_ec_dom_par_ref_t__set_by_builtin_id(
      &ecc_dp__t,
      tls_ctx__pt->chosen_ecc_dp_internal_id__u8
    )
  );

  FLEA_CCALL(
    THR_flea_public_key_t__ctor_ecc(
      peer_pubkey__pt,
      &peer_enc_pubpoint_vec__t,
      &ecc_dp__t
    )
  );

  if(peer_enc_pubpoint_len__u8 == 0)
  {
    FLEA_THROW("invalid public point length for ecka kdf-ansi-X9.63", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  result_len__alu8 = (peer_enc_pubpoint_len__u8 - 1) / 2;
#  ifdef FLEA_STACK_MODE
  if(result_len__alu8 > FLEA_ECC_MAX_MOD_BYTE_SIZE)
  {
    FLEA_THROW("field size not supported", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
#  endif /* ifdef FLEA_STACK_MODE */
  FLEA_CCALL(THR_flea_byte_vec_t__resize(premaster_secret__pt, result_len__alu8));

  FLEA_CCALL(
    THR_flea_ecka__compute_raw(
      peer_enc_pubpoint__bu8,
      peer_enc_pubpoint_len__u8,
      priv_key__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.data__pu8,
      priv_key__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.len__dtl,
      premaster_secret__pt->data__pu8,
      &result_len__alu8,
      &ecc_dp__t
    )
  );

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(peer_enc_pubpoint__bu8);
  );
} /* THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret */

# endif /* ifdef FLEA_HAVE_TLS_CS_ECDHE */

void flea_tls_ctx_t__begin_handshake(flea_tls_ctx_t* tls_ctx__pt)
{
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
  flea_byte_vec_t__reset(&tls_ctx__pt->peer_ee_cert_data__t);
  flea_x509_cert_ref_t__dtor(&tls_ctx__pt->peer_ee_cert_ref__t);
# endif
# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
  tls_ctx__pt->peer_root_cert_set__u8 = FLEA_FALSE;
  flea_x509_cert_ref_t__dtor(&tls_ctx__pt->peer_root_cert_ref__t);
# endif
}

void flea_tls_ctx_t__dtor(flea_tls_ctx_t* tls_ctx__pt)
{
  flea_tls_rec_prot_t__dtor(&tls_ctx__pt->rec_prot__t);
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
  flea_byte_vec_t__dtor(&tls_ctx__pt->peer_ee_cert_data__t);
  flea_x509_cert_ref_t__dtor(&tls_ctx__pt->peer_ee_cert_ref__t);
  flea_x509_cert_ref_t__dtor(&tls_ctx__pt->peer_root_cert_ref__t);
# endif
  FLEA_FREE_BUF_FINAL_SECRET_ARR(tls_ctx__pt->master_secret__bu8, FLEA_TLS_MASTER_SECRET_SIZE);
# ifdef FLEA_HEAP_MODE
  FLEA_FREE_MEM_CHK_NULL(tls_ctx__pt->own_vfy_data__bu8);
# endif
}

#endif /* ifdef FLEA_HAVE_TLS */
