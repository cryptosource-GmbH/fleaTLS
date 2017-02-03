/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls__H_
#define _flea_tls__H_

#include "internal/common/build_config.h"
#include "flea/types.h"
#include "flea/pubkey.h"
#include "flea/hash.h"
#include "flea/mac.h"
#include "flea/rw_stream.h"
#include "internal/common/tls_ciph_suite.h"
#include "internal/common/tls_rec_prot.h"


#ifdef __cplusplus
extern "C" {
#endif


// defines for max sizes to allocate on the stack
// TODO: cleaner solution?
#define FLEA_TLS_MAX_MAC_SIZE         32
#define FLEA_TLS_MAX_MAC_KEY_SIZE     32
#define FLEA_TLS_MAX_IV_SIZE          32
#define FLEA_TLS_MAX_RECORD_DATA_SIZE 16384 // 2^14 max record sizeof
#define FLEA_TLS_MAX_PADDING_SIZE     255   // each byte must hold the padding value => 255 is max


typedef enum { PRF_LABEL_TEST, PRF_LABEL_CLIENT_FINISHED, PRF_LABEL_SERVER_FINISHED, PRF_LABEL_MASTER_SECRET,
               PRF_LABEL_KEY_EXPANSION } PRFLabel;

typedef enum
{
  HANDSHAKE_TYPE_HELLO_REQUEST       = 0,
  HANDSHAKE_TYPE_CLIENT_HELLO        = 1,
  HANDSHAKE_TYPE_SERVER_HELLO        = 2,
  HANDSHAKE_TYPE_NEW_SESSION_TICKET  = 4,
  HANDSHAKE_TYPE_CERTIFICATE         = 11,
  HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
  HANDSHAKE_TYPE_CERTIFCATE_REQUEST  = 13,
  HANDSHAKE_TYPE_SERVER_HELLO_DONE   = 14,
  HANDSHAKE_TYPE_CERTIFICATE_VERIFY  = 15,
  HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
  HANDSHAKE_TYPE_FINISHED            = 20
} HandshakeType;

typedef struct
{
  RecordType                   record_type;
  ContentType                  content_type;
  flea_tls__protocol_version_t version;
  flea_u16_t                   length;
  flea_u8_t                    *data;
} Record;

typedef struct
{
  flea_u8_t gmt_unix_time[4];
  flea_u8_t random_bytes[28];
} Random;


// TODO: Extensions

typedef struct
{
  HandshakeType type;
  flea_u32_t    length; // actually 24 Bit type !!
  flea_u8_t     *data;
} HandshakeMessage;

typedef struct
{
  flea_tls__protocol_version_t client_version;
  Random                       random;
  flea_u8_t                    *session_id;
  flea_u8_t                    session_id_length;
  flea_u8_t                    *cipher_suites;
  flea_u16_t                   cipher_suites_length;
  CompressionMethod            *compression_methods;
  flea_u8_t                    compression_methods_length;
  flea_u8_t                    *extensions; // 2^16 bytes
} flea_tls__client_hello_t;

typedef struct
{
  flea_tls__protocol_version_t server_version;
  Random                       random;
  flea_u8_t                    *session_id;
  flea_u8_t                    session_id_length;
  flea_u8_t                    cipher_suite;
  CompressionMethod            compression_method;
  flea_u8_t                    compression_methods_length;
  flea_u8_t                    *extensions; // 2^16 bytes
} ServerHello;

typedef struct
{
  flea_u8_t  *certificate_list;
  flea_u32_t certificate_list_length;
} Certificate;

typedef enum                 // dhe_dss, dhe_rsa, dh_anon,
{ KEY_EXCHANGE_ALGORITHM_RSA // ,
  // dh_dss, dh_rsa
} KeyExchangeAlgorithm;

typedef struct
{
  KeyExchangeAlgorithm algorithm;

  /**
   * struct {
   *      ProtocolVersion client_version;
   *      opaque random[46];
   *  } PreMasterSecret;
   *
   *  client_version
   *     The latest (newest) version supported by the client.  This is
   *     used to detect version rollback attacks.
   *
   *  random
   *     46 securely-generated random bytes.
   *
   *  struct {
   *      public-key-encrypted PreMasterSecret pre_master_secret;
   *  } EncryptedPreMasterSecret;
   */
  flea_u8_t  premaster_secret[256]; /* TODO: variable */
  flea_u8_t  *encrypted_premaster_secret;
  flea_u16_t encrypted_premaster_secret_length;
  flea_u8_t  *ClientDiffieHellmanPublic;
} flea_tls__client_key_ex_t;

typedef enum { CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC = 1 } CHANGE_CIPHER_SPEC_TYPE;

typedef struct
{
  CHANGE_CIPHER_SPEC_TYPE change_cipher_spec;
} ChangeCipherSpec;

/*typedef struct
{
  flea_u8_t  *verify_data;
  flea_u32_t verify_data_length; // 12 for all cipher suites defined in TLS 1.2 - RFC 5246. is 24 bit!!
} flea_tls__finished_t;
*/
/**
 * ServerHelloDone: no content, no struct needed
 */

typedef enum
{
  FLEA_TLS_CLIENT,
  FLEA_TLS_SERVER
} flea_tls__connection_end_t;

typedef enum
{
  FLEA_TLS_HMAC_SHA1,
  FLEA_TLS_HMAC_SHA256
} flea_tls__mac_algorithm_t;

typedef enum
{
  FLEA_TLS_BCA_AES,
  FLEA_TLS_BCA_TRIPLE_DES,
  FLEA_TLS_BCA_NULL
} flea_tls__bulk_cipher_alg_t;

typedef enum
{
  FLEA_TLS_CIPHER_TYPE_STREAM,
  FLEA_TLS_CIPHER_TYPE_BLOCK,
  FLEA_TLS_CIPHER_TYPE_AEAD
} flea_tls__cipher_type_t;

typedef enum
{
  FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY                = 0,
  FLEA_TLS_ALERT_DESC_UNEXPECTED_MESSAGE          = 10,
  FLEA_TLS_ALERT_DESC_BAD_RECORD_MAC              = 20,
  FLEA_TLS_ALERT_DESC_DECRYPTION_FAILED_RESERVED  = 21,
  FLEA_TLS_ALERT_DESC_RECORD_OVERFLOW             = 22,
  FLEA_TLS_ALERT_DESC_DECOMPRESSION_FAILURE       = 30,
  FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE           = 40,
  FLEA_TLS_ALERT_DESC_NO_CERTIFICATE_RESERVED     = 41,
  FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE             = 42,
  FLEA_TLS_ALERT_DESC_UNSUPPORTED_CERTIFICATE     = 43,
  FLEA_TLS_ALERT_DESC_CERTIFICATE_REVOKED         = 44,
  FLEA_TLS_ALERT_DESC_CERTIFICATE_EXPIRED         = 45,
  FLEA_TLS_ALERT_DESC_CERTIFICATE_UNKNOWN         = 46,
  FLEA_TLS_ALERT_DESC_ILLEGAL_PARAMETER           = 47,
  FLEA_TLS_ALERT_DESC_UNKNOWN_CA                  = 48,
  FLEA_TLS_ALERT_DESC_ACCESS_DENIED               = 49,
  FLEA_TLS_ALERT_DESC_DECODE_ERROR                = 50,
  FLEA_TLS_ALERT_DESC_DECRYPT_ERROR               = 51,
  FLEA_TLS_ALERT_DESC_EXPORT_RESTRICTION_RESERVED = 60,
  FLEA_TLS_ALERT_DESC_PROTOCOL_VERSION            = 70,
  FLEA_TLS_ALERT_DESC_INSUFFICIENT_SECURITY       = 71,
  FLEA_TLS_ALERT_DESC_INTERNAL_ERROR              = 80,
  FLEA_TLS_ALERT_DESC_USER_CANCELED               = 90,
  FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION            = 100,
  FLEA_TLS_ALERT_DESC_UNSUPPORTED_EXTENSION       = 110
} flea_tls__alert_description_t;

typedef enum
{
  FLEA_TLS_ALERT_LEVEL_WARNING = 1,
  FLEA_TLS_ALERT_LEVEL_FATAL   = 2
} flea_tls__alert_level_t;


extern flea_tls__cipher_suite_t cipher_suites[2];


/**
 * Security Parameters
 *
 *  PRFAlgorithm           prf_algorithm;
 *  BulkCipherAlgorithm    bulk_cipher_algorithm;
 *  CipherType             cipher_type;
 *  uint8                  enc_key_length;
 *  uint8                  block_length;
 *  uint8                  fixed_iv_length;
 *  uint8                  record_iv_length;
 *  MACAlgorithm           mac_algorithm;
 *  uint8                  mac_length;
 *  uint8                  mac_key_length;
 *  CompressionMethod      compression_algorithm;
 *  opaque                 master_secret[48];
 *  opaque                 client_random[32];
 *  opaque                 server_random[32];
 */
typedef struct
{
  flea_tls__connection_end_t  connection_end;        /* Server or Client */
  flea_tls__prf_algorithm_t   prf_algorithm;         /* PRF algorithm to use */
  flea_tls__bulk_cipher_alg_t bulk_cipher_algorithm; /* Encryption Algorithm to use */
  flea_tls__cipher_type_t     cipher_type;           /* Block, Stream or AEAD */

  /*	flea_u8_t enc_key_length;
   * flea_u8_t block_length;
   * flea_u8_t fixed_iv_length;
   * flea_u8_t record_iv_length;*/
  flea_tls__mac_algorithm_t mac_algorithm; /* negotiated mac algorithm */

  /*flea_u8_t mac_length;
   * flea_u8_t mac_key_length;*/
  CompressionMethod *compression_methods; /* Pool of compression methods that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  flea_u32_t        compression_methods_len;
  flea_u8_t         master_secret[48]; /* symmetric keys are derived from this */
  Random            client_random;     /* random value that the client sends */
  Random            server_random;     /* random value that the server sends */
} flea_tls__security_parameters_t;

typedef struct
{
  flea_u8_t  *record_hdr__pu8;
  flea_u8_t  *message__pu8;
  flea_u16_t message_len__u16;
  flea_u16_t allocated_message_len__u16;
} flea_tls_record_t;

#define flea_tls_record_t__SET_BUF(__p, __buf, __buf_len) \
  do { (__p)->record_hdr__pu8  = (__buf); \
       (__p)->message__pu8     = (__buf) + 5; \
       (__p)->message_len__u16 = 0; \
       (__p)->allocated_message_len__u16 = (__buf_len) - 5; \
  } while(0)


typedef struct
{
  /* Security Parameters negotiated during handshake */
  flea_tls__security_parameters_t *security_parameters; // can be deleted from memory (or saved for later resumption?) TODO: check again how it works, maybe only store master secret

  /*
   * Connection States
   *
   *  Once the security parameters have been set and the keys have been
   *  generated, the connection states can be instantiated by making them
   *  the current states.  These current states MUST be updated for each
   *  record processed.
   *
   */
  flea_tls__connection_state_t *active_write_connection_state; /* Swap active and pending after a ChangeCipherSpec message */
  flea_tls__connection_state_t *active_read_connection_state;  /* and reinitialized pending */
  flea_tls__connection_state_t *pending_write_connection_state;
  flea_tls__connection_state_t *pending_read_connection_state;

  /*
   * Other information or configuration
   */

  flea_u8_t                    *allowed_cipher_suites; /* Pool of ciphersuites that can be negotiated. Priority (in case of server): Prefer first over second and so on */
  flea_u32_t                   allowed_cipher_suites_len;
  flea_u8_t                    selected_cipher_suite[2];

  /* TODO: Where do I allocate the memory? inside __ctor seems pointless with stack usage */
  flea_public_key_t            server_pubkey; /* Public Key of server to use (Key Exchange) */

  flea_tls__protocol_version_t version; /* max. supported TLS version */

  flea_u8_t                    session_id[32]; /* Session ID for later resumption */
  flea_u8_t                    session_id_len;

  flea_u8_t                    *premaster_secret; // shall be deleted after master_Secret is calculated
  flea_bool_t                  resumption;

  flea_u8_t                    key_block[128]; // size for key block for aes256+sha256 - max size for all ciphersuites in RFC

  flea_rw_stream_t             *rw_stream__pt;
} flea_tls_ctx_t;
// int flea_tls_connection();

flea_err_t
flea_tls_ctx_t__ctor(flea_tls_ctx_t *ctx, flea_u8_t *session_id, flea_u8_t session_id_len);

flea_err_t
THR_flea_tls__client_handshake(int socket_fd, flea_tls_ctx_t *tls_ctx, flea_rw_stream_t *rw_stream__pt);
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
