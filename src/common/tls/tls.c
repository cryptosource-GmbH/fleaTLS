/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


/*
	TODO: read_next_handshake_message !

	TODO:
		- QUESTION: do we need the structs at all? Simply save the important parts in the tls_ctx (e.g. security_parameters)
		- Cipher Suites: use new struct and array of supported ciphersuites.
*/


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/tls.h"

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h> // for close

#include "flea/pubkey.h"
#include "flea/asn1_date.h"
#include "flea/cert_chain.h"
#include "flea/ber_dec.h"
#include "flea/mac.h"
#include "flea/rng.h"
#include "flea/hash.h"
#include "flea/block_cipher.h"
#include "flea/bin_utils.h"

#include <stdio.h>
flea_u8_t key_block[128]; // size for key block for aes256+sha256. TODO: move from global scope into tls_context or something

flea_u8_t trust_anchor[] = {0x30, 0x82, 0x03, 0x7f, 0x30, 0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xfe, 0x12, 0x36, 0x42, 0xa1, 0xb6, 0xf7, 0x11, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xa5, 0x70, 0x42, 0x71, 0x64, 0xdf, 0xfa, 0x98, 0x43, 0x8a, 0x13, 0x5f, 0xe3, 0x7d, 0xed, 0x27, 0xff, 0x52, 0x3a, 0x6b, 0x7f, 0x0f, 0xd6, 0x80, 0xaa, 0xfd, 0x2e, 0xf9, 0xb7, 0xcf, 0x6b, 0x46, 0x72, 0x91, 0x95, 0x39, 0x44, 0xc1, 0xbf, 0x69, 0x9e, 0x65, 0xab, 0xbd, 0xa7, 0xe6, 0x3c, 0xfd, 0x12, 0x09, 0xa6, 0xda, 0x1e, 0xf4, 0x12, 0x9b, 0x0d, 0xd6, 0x5c, 0x6c, 0xdf, 0x64, 0x77, 0xfe, 0x35, 0x2d, 0xd9, 0xad, 0x99, 0xc1, 0x47, 0x31, 0xef, 0x95, 0x23, 0x38, 0x48, 0xd7, 0xa6, 0x84, 0x69, 0x6c, 0x4d, 0x37, 0xe8, 0x29, 0xd3, 0xb4, 0x68, 0x03, 0x19, 0xdc, 0xb1, 0xd1, 0xfd, 0xfb, 0x97, 0x61, 0x50, 0xe7, 0x2a, 0xa0, 0xfd, 0x7c, 0x8f, 0x51, 0x88, 0x0b, 0x5d, 0x74, 0xce, 0xb6, 0xa5, 0x65, 0x53, 0xb2, 0x0d, 0xdf, 0xb5, 0x7a, 0xe1, 0x3c, 0x98, 0x6e, 0x29, 0xa7, 0x90, 0x75, 0x13, 0xac, 0x22, 0x92, 0xdb, 0xe6, 0x8c, 0x6f, 0x32, 0xa7, 0x42, 0xa4, 0xa4, 0x5c, 0x04, 0xdb, 0x04, 0x95, 0x34, 0x13, 0xe0, 0xa1, 0x47, 0x00, 0x21, 0xf6, 0xa1, 0xa7, 0xaa, 0x0e, 0x97, 0xc5, 0x2b, 0x64, 0x00, 0x74, 0xdd, 0x57, 0xe3, 0x03, 0xe0, 0xb8, 0xc5, 0x4e, 0xe3, 0x3e, 0xf0, 0x33, 0x7d, 0x5e, 0x82, 0xda, 0xaa, 0x04, 0x0d, 0xdc, 0x80, 0x14, 0xaf, 0x30, 0x10, 0x9c, 0x5b, 0xb8, 0xd2, 0xb6, 0x76, 0x6c, 0x10, 0x27, 0xfd, 0x6e, 0xaa, 0xc2, 0x70, 0x7e, 0x0d, 0x37, 0x2c, 0x28, 0x81, 0x26, 0xc8, 0xeb, 0x7c, 0x4b, 0x8f, 0xda, 0x7b, 0x02, 0xb0, 0x51, 0x92, 0x3d, 0x3d, 0x5e, 0x53, 0xfa, 0xcb, 0x43, 0x4f, 0xef, 0x1e, 0x61, 0xe5, 0xb9, 0x2c, 0x08, 0x77, 0xff, 0x65, 0x77, 0x13, 0x4d, 0xd4, 0xcb, 0x2e, 0x7f, 0x9d, 0xe2, 0x1a, 0xc3, 0x19, 0x84, 0xb1, 0x52, 0x9d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7b, 0x18, 0xad, 0x25, 0x86, 0x17, 0x93, 0x93, 0xcb, 0x01, 0xe1, 0x07, 0xce, 0xfa, 0x37, 0x96, 0x5f, 0x17, 0x95, 0x1d, 0x76, 0xf3, 0x04, 0x36, 0x81, 0x64, 0x78, 0x2a, 0xc2, 0xcc, 0xbd, 0x77, 0xf7, 0x59, 0xeb, 0x9a, 0xf7, 0xb3, 0xfc, 0x1a, 0x30, 0xfe, 0x6f, 0x6e, 0x02, 0xc6, 0x2d, 0x4d, 0x79, 0x25, 0xaf, 0x98, 0xb4, 0xab, 0x3e, 0x25, 0xfc, 0xef, 0x98, 0x26, 0x0f, 0x6a, 0x0a, 0x74, 0x5b, 0x4f, 0x3a, 0x6c, 0xd6, 0x42, 0x56, 0xd9, 0x25, 0x0a, 0x1e, 0x3a, 0x4c, 0x74, 0xe9, 0x28, 0xcf, 0x7d, 0xe9, 0x48, 0xdc, 0xd6, 0xf4, 0x23, 0xf7, 0x2e, 0xc9, 0x50, 0xb7, 0xad, 0x22, 0x9b, 0xdf, 0x60, 0xcf, 0x2f, 0x4b, 0x98, 0x79, 0x3d, 0x56, 0xf0, 0x03, 0xfd, 0xe1, 0x61, 0x12, 0xed, 0x44, 0xe8, 0x22, 0xce, 0x4d, 0x41, 0xe7, 0xd4, 0x9c, 0xf9, 0x12, 0x57, 0x12, 0xb0, 0x20, 0xb3, 0xfa, 0xf5, 0x09, 0x8b, 0xc6, 0x38, 0xc2, 0x31, 0x41, 0xe8, 0xf3, 0x1c, 0x9a, 0xb7, 0x87, 0x73, 0x64, 0x29, 0xc5, 0x0f, 0x8e, 0x2d, 0x80, 0xbd, 0x54, 0x16, 0x6d, 0xc2, 0xcd, 0x5f, 0x0c, 0x12, 0xe0, 0xd2, 0x6b, 0xce, 0x99, 0x53, 0x7b, 0xa8, 0x38, 0x4e, 0x17, 0xea, 0xc1, 0x70, 0x9b, 0x33, 0x39, 0xc2, 0x83, 0x11, 0xba, 0xbd, 0x9b, 0x79, 0x09, 0xc5, 0x01, 0xea, 0x2d, 0xc6, 0x56, 0xf2, 0x9a, 0x14, 0x68, 0x37, 0xb2, 0x28, 0xb0, 0x60, 0xf0, 0xc6, 0xf4, 0xa6, 0x1e, 0xeb, 0x2b, 0x1d, 0x0e, 0xa0, 0x58, 0xfc, 0xd8, 0x2c, 0x01, 0xa3, 0xcf, 0xae, 0xa8, 0x3b, 0x49, 0x9e, 0xad, 0x51, 0xe7, 0x08, 0x65, 0x8c, 0x5c, 0x33, 0x54, 0x04, 0x14, 0x48, 0xf1, 0x79, 0xab, 0x33, 0xf5, 0xd4, 0xe0, 0xef, 0x1a, 0x62, 0x13, 0x48, 0xda, 0x52, 0x3e, 0x02, 0x8f, 0x64, 0xba, 0x8e, 0xf1, 0x88};

typedef enum { PRF_LABEL_CLIENT_FINISHED, PRF_LABEL_SERVER_FINISHED, PRF_LABEL_MASTER_SECRET, PRF_LABEL_KEY_EXPANSION } PRFLabel;


typedef enum
{
	TLS_NULL_WITH_NULL_NULL				= 0x0000,
	TLS_RSA_WITH_AES_256_CBC_SHA256 	= 0x003D
} flea_tls__cipher_suite_id_t;

typedef enum
{
	HANDSHAKE_TYPE_HELLO_REQUEST = 0,
	HANDSHAKE_TYPE_CLIENT_HELLO = 1,
	HANDSHAKE_TYPE_SERVER_HELLO = 2,
	HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4,
    HANDSHAKE_TYPE_CERTIFICATE = 11,
	HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
    HANDSHAKE_TYPE_CERTIFCATE_REQUEST = 13,
	HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15,
	HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
    HANDSHAKE_TYPE_FINISHED = 20
} HandshakeType;


typedef enum
{
	 CONTENT_TYPE_CHANGE_CIPHER_SPEC=20,
	 CONTENT_TYPE_ALERT=21,
	 CONTENT_TYPE_HANDSHAKE=22,
	 CONTENT_TYPE_APPLICATION_DATA=23,
	 CONTENT_TYPE_HEARTBEAT=24
} ContentType;

typedef enum
{
	 RECORD_TYPE_PLAINTEXT,
	 RECORD_TYPE_CIPHERTEXT,
	 RECORD_TYPE_COMPRESSED,
} RecordType;

typedef struct {
	flea_u8_t gmt_unix_time[4];
	flea_u8_t random_bytes[28];
} Random;


typedef struct {
	flea_u8_t major;
	flea_u8_t minor;
} flea_tls__protocol_version_t;

typedef struct {
	RecordType record_type;
	ContentType content_type;
	flea_tls__protocol_version_t version;
	flea_u16_t length;
	flea_u8_t *data;
} Record;

typedef enum {
	NO_COMPRESSION=0,
	COMPRESSION=255
} CompressionMethod;

// TODO: Extensions


typedef struct {
   HandshakeType type;
   flea_u32_t length;	// actually 24 Bit type !!
   flea_u8_t* data;
} HandshakeMessage;

typedef struct {
	flea_tls__protocol_version_t client_version;
	Random random;
	flea_u8_t* session_id;
	flea_u8_t session_id_length;
	flea_u8_t* cipher_suites;
	flea_u16_t cipher_suites_length;
	CompressionMethod* compression_methods;
	flea_u8_t compression_methods_length;
	flea_u8_t* extensions;	// 2^16 bytes
} flea_tls__client_hello_t;

typedef struct {
	flea_tls__protocol_version_t server_version;
	Random random;
	flea_u8_t* session_id;
	flea_u8_t session_id_length;
	flea_u8_t cipher_suite;
	CompressionMethod compression_method;
	flea_u8_t compression_methods_length;
	flea_u8_t* extensions;	// 2^16 bytes
} ServerHello;

typedef struct {
	flea_u8_t* certificate_list;
	flea_u32_t certificate_list_length;
} Certificate;

typedef enum { //dhe_dss, dhe_rsa, dh_anon,
	 KEY_EXCHANGE_ALGORITHM_RSA //,
	 //dh_dss, dh_rsa
 } KeyExchangeAlgorithm;


typedef struct {
	KeyExchangeAlgorithm algorithm;
	/**
	struct {
          ProtocolVersion client_version;
          opaque random[46];
      } PreMasterSecret;

      client_version
         The latest (newest) version supported by the client.  This is
         used to detect version rollback attacks.

      random
         46 securely-generated random bytes.

      struct {
          public-key-encrypted PreMasterSecret pre_master_secret;
      } EncryptedPreMasterSecret;
	*/
	flea_u8_t premaster_secret[256];	/* TODO: variable */
	flea_u8_t* encrypted_premaster_secret;
	flea_u16_t encrypted_premaster_secret_length;
	flea_u8_t* ClientDiffieHellmanPublic;
} flea_tls__client_key_ex_t;

typedef enum {CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC = 1} CHANGE_CIPHER_SPEC_TYPE;

typedef struct {
	CHANGE_CIPHER_SPEC_TYPE change_cipher_spec;
} ChangeCipherSpec;


typedef struct {
  flea_u8_t* verify_data;
  flea_u32_t verify_data_length;	// 12 for all cipher suites defined in TLS 1.2 - RFC 5246. is 24 bit!!
} flea_tls__finished_t;

/**
	ServerHelloDone: no content, no struct needed
*/

typedef enum {
	FLEA_TLS_CLIENT,
	FLEA_TLS_SERVER
} flea_tls__connection_end_t;

typedef enum {
	FLEA_TLS_HMAC_SHA1,
	FLEA_TLS_HMAC_SHA256
} flea_tls__mac_algorithm_t;

typedef enum {
	FLEA_TLS_BCA_AES,
	FLEA_TLS_BCA_TRIPLE_DES,
	FLEA_TLS_BCA_NULL
} flea_tls__bulk_cipher_alg_t;


typedef enum {
	FLEA_TLS_CIPHER_TYPE_STREAM,
	FLEA_TLS_CIPHER_TYPE_BLOCK,
	FLEA_TLS_CIPHER_TYPE_AEAD
} flea_tls__cipher_type_t;


typedef enum {
	FLEA_TLS_PRF_SHA256
} flea_tls__prf_algorithm_t;

typedef struct {
	flea_tls__cipher_suite_id_t id;

	flea_block_cipher_id_t cipher;	// flea_des_single, flea_tdes_2key, flea_tdes_3key, flea_desx, flea_aes128, flea_aes192, flea_aes256;

	flea_u8_t block_size;	// RFC: 8 bits => flea_block_cipher__get_block_size
	flea_u8_t iv_size;		// RFC: 8 bits
	flea_u8_t enc_key_size;	// RFC: 8 bits => flea_block_cipher__get_key_size
	flea_u8_t mac_key_size;	// RFC: 8 bits
	flea_u8_t mac_size;	// RFC: 8 bits


	flea_mac_id_t 	mac_algorithm;	// default: flea_hmac_sha256
	flea_hash_id_t	hash_algorithm; // default: flea_sha256

	flea_tls__prf_algorithm_t prf_algorithm;
} flea_tls__cipher_suite_t;

flea_tls__cipher_suite_t cipher_suites[] =
{
	{TLS_NULL_WITH_NULL_NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{TLS_RSA_WITH_AES_256_CBC_SHA256, flea_aes256, 16, 16, 32, 32, 32, flea_hmac_sha256, flea_sha256, FLEA_TLS_PRF_SHA256}
};

typedef struct {
	/*
		RFC 5246 6.1.  Connection States
	*/
	// TODO:
	flea_tls__cipher_suite_t* cipher_suite;


	/* keys */
	flea_u8_t* mac_key;	//length inside cipher_suite
	flea_u8_t* enc_key;
	flea_u8_t* iv;

	/* compression state */
	CompressionMethod compression_method;

	/* sequence number */
	flea_u64_t sequence_number;

	// TODO: maybe need to add more fields for stream ciphers

} flea_tls__connection_state_t;

/**
	Security Parameters

	  PRFAlgorithm           prf_algorithm;
	  BulkCipherAlgorithm    bulk_cipher_algorithm;
	  CipherType             cipher_type;
	  uint8                  enc_key_length;
	  uint8                  block_length;
	  uint8                  fixed_iv_length;
	  uint8                  record_iv_length;
	  MACAlgorithm           mac_algorithm;
	  uint8                  mac_length;
	  uint8                  mac_key_length;
	  CompressionMethod      compression_algorithm;
	  opaque                 master_secret[48];
	  opaque                 client_random[32];
	  opaque                 server_random[32];
*/
typedef struct {
	flea_tls__connection_end_t connection_end;			/* Server or Client */
	flea_tls__prf_algorithm_t prf_algorithm;			/* PRF algorithm to use */
	flea_tls__bulk_cipher_alg_t bulk_cipher_algorithm;	/* Encryption Algorithm to use */
	flea_tls__cipher_type_t cipher_type;				/* Block, Stream or AEAD */
/*	flea_u8_t enc_key_length;
	flea_u8_t block_length;
	flea_u8_t fixed_iv_length;
	flea_u8_t record_iv_length;*/
	flea_tls__mac_algorithm_t mac_algorithm;			/* negotiated mac algorithm */
	/*flea_u8_t mac_length;
	flea_u8_t mac_key_length;*/
	CompressionMethod* compression_methods;						/* Pool of compression methods that can be negotiated. Priority (in case of server): Prefer first over second and so on */
	flea_u32_t compression_methods_len;
	flea_u8_t master_secret[48];						/* symmetric keys are derived from this */
	Random client_random;								/* random value that the client sends */
	Random server_random;								/* random value that the server sends */
} flea_tls__security_parameters_t;

typedef struct {
	/* Security Parameters negotiated during handshake */
	flea_tls__security_parameters_t* security_parameters;	// can be deleted from memory (or saved for later resumption?) TODO: check again how it works, maybe only store master secret

	/*
		Connection States

			Once the security parameters have been set and the keys have been
			generated, the connection states can be instantiated by making them
			the current states.  These current states MUST be updated for each
			record processed.

	*/
	flea_tls__connection_state_t* active_write_connection_state;	/* Swap active and pending after a ChangeCipherSpec message */
	flea_tls__connection_state_t* active_read_connection_state;		/* and reinitialized pending */
	flea_tls__connection_state_t* pending_write_connection_state;
	flea_tls__connection_state_t* pending_read_connection_state;

	/*
		Other information or configuration
	*/

	flea_u8_t* allowed_cipher_suites;				/* Pool of ciphersuites that can be negotiated. Priority (in case of server): Prefer first over second and so on */
	flea_u32_t allowed_cipher_suites_len;
	flea_u8_t selected_cipher_suite[2];

	/* TODO: Where do I allocate the memory? inside __ctor seems pointless with stack usage */
	flea_public_key_t server_pubkey;				/* Public Key of server to use (Key Exchange) */

	flea_tls__protocol_version_t version;			/* max. supported TLS version */

	flea_u8_t session_id[32];							/* Session ID for later resumption */
	flea_u8_t session_id_len;

	flea_u8_t* premaster_secret; // shall be deleted after master_Secret is calculated
	flea_bool_t resumption;

} flea_tls_ctx_t;


/* Falko: use "const" for input data*/
flea_err_t P_Hash(flea_u8_t* secret, flea_u16_t secret_length, flea_u8_t* seed, flea_u16_t seed_length, flea_u16_t res_length, flea_u8_t* data_out)
{
	flea_u16_t hash_len = 32;
	flea_u16_t A_len;
	if (seed_length > hash_len)
	{
		A_len = seed_length;
	}
	else
	{
		A_len = hash_len;
	}
	flea_u8_t A[A_len]; /* Falko: dynamically-sized stack buffers may not be used */
	flea_u8_t A2[A_len];
	flea_u8_t tmp_input[hash_len];
	flea_u8_t tmp_output[hash_len];

	// A(0) = seed
	memcpy(A, seed, seed_length);

	// expand to length bytes
	flea_u16_t current_length = 0;
	flea_al_u8_t len = hash_len;
	flea_bool_t first = FLEA_TRUE;

	FLEA_THR_BEG_FUNC();
	while (current_length < res_length)
	{
		// A(i) = HMAC_hash(secret, A(i-1))
		if (first)
		{
      /* Falko: use CCALL */
			FLEA_CCALL(THR_flea_mac__compute_mac(flea_hmac_sha256, secret, secret_length, A, seed_length, A2, &len));
			first = FLEA_FALSE;
		}
		else
		{
			FLEA_CCALL(THR_flea_mac__compute_mac(flea_hmac_sha256, secret, secret_length, A, hash_len, A2, &len));
      // Ausgabe direkt nach tmp_input scheint am einfachsten
		}
// Falko A2 => A => tmp_input ? kann hier nicht ein Schritt gespart werden?
		memcpy(A, A2, hash_len);

		// calculate A(i) + seed
		memcpy(tmp_input, A, hash_len);
		memcpy(tmp_input+hash_len, seed, seed_length);

		// + HMAC_hash(secret, A(i) + seed)
		// concatenate to the result
    // Falko: das kann direkt nach data_out geschrieben werden, mit entsprechend
    // angepasster Ausgabelaenge:
		FLEA_CCALL(THR_flea_mac__compute_mac(flea_hmac_sha256, secret, secret_length, tmp_input, hash_len+seed_length, tmp_output, &len));
    /* Falko: dann unoetig ( davon abgesehen sollte nur ein Aufruf mit
     * entsprechend berechneter Laenge erfolgen ): */
		if (current_length+hash_len < res_length)
		{
			memcpy(data_out+current_length, tmp_output, hash_len);
		}
		else
		{
			memcpy(data_out+current_length, tmp_output, res_length - current_length);
		}
		current_length += hash_len;
	}
	FLEA_THR_FIN_SEC_empty();
}
/**
      P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                             HMAC_hash(secret, A(2) + seed) +
                             HMAC_hash(secret, A(3) + seed) + ...

   where + indicates concatenation.

   A() is defined as:
      A(0) = seed
      A(i) = HMAC_hash(secret, A(i-1))


      PRF(secret, label, seed) = P_<hash>(secret, label + seed)

	  P_Hash is Sha256 for all ciphers defined in RFC5246


	  FinishedMessage:
	  verify_data
	           PRF(master_secret, finished_label, Hash(handshake_messages))
	              [0..verify_data_length-1];
*/
// length: how long should the output be. 12 Octets = 96 Bits
flea_err_t PRF(flea_u8_t* secret, flea_u8_t secret_length, PRFLabel label, flea_u8_t* seed, flea_u16_t seed_length, flea_u16_t result_length, flea_u8_t* result) {
	FLEA_THR_BEG_FUNC();

	/**
		TODO: no fixed sha256
	*/
	flea_u8_t client_finished[] = {99, 108, 105, 101, 110, 116, 32, 102, 105, 110, 105, 115, 104, 101, 100};
	flea_u8_t master_secret[] = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
	flea_u8_t key_expansion[] = {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};


	flea_u8_t p_hash_seed[500];	// arbitrarily chosen: TODO change
	flea_u16_t p_hash_seed_length;

	switch (label) {
		case PRF_LABEL_CLIENT_FINISHED:
			memcpy(p_hash_seed, client_finished, sizeof(client_finished));
			memcpy(p_hash_seed+sizeof(client_finished), seed, seed_length);
			p_hash_seed_length = sizeof(client_finished) + seed_length;
			break;
		case PRF_LABEL_MASTER_SECRET:
			memcpy(p_hash_seed, master_secret, sizeof(master_secret));
			memcpy(p_hash_seed+sizeof(master_secret), seed, seed_length);
			p_hash_seed_length = sizeof(master_secret) + seed_length;
			break;
		case PRF_LABEL_KEY_EXPANSION:
			memcpy(p_hash_seed, key_expansion, sizeof(key_expansion));
			memcpy(p_hash_seed+sizeof(key_expansion), seed, seed_length);
			p_hash_seed_length = sizeof(key_expansion) + seed_length;
			break;
		case PRF_LABEL_SERVER_FINISHED: break;
	}
	FLEA_CCALL(P_Hash(secret, secret_length, p_hash_seed, p_hash_seed_length, result_length, result));
	FLEA_THR_FIN_SEC_empty();
}

/*
key_block = PRF(SecurityParameters.master_secret,
				  "key expansion",
				  SecurityParameters.server_random +
				  SecurityParameters.client_random);
*/
flea_err_t generate_key_block_2(flea_tls_ctx_t* tls_ctx, flea_u8_t* key_block2)
{
	FLEA_THR_BEG_FUNC();
	flea_u8_t seed[64];
	memcpy(seed, tls_ctx->security_parameters->server_random.gmt_unix_time, 4);
	memcpy(seed+4, tls_ctx->security_parameters->server_random.random_bytes, 28);
	memcpy(seed+32, tls_ctx->security_parameters->client_random.gmt_unix_time, 4);
	memcpy(seed+36, tls_ctx->security_parameters->client_random.random_bytes, 28);

	FLEA_CCALL(PRF(tls_ctx->security_parameters->master_secret, 48, PRF_LABEL_KEY_EXPANSION, seed, sizeof(seed), 128, key_block2));
	FLEA_THR_FIN_SEC_empty();
}

flea_err_t generate_key_block(flea_u8_t* master_secret, Random client_random, Random server_random) {
	FLEA_THR_BEG_FUNC();
	flea_u8_t seed[64];
	memcpy(seed, server_random.gmt_unix_time, 4);
	memcpy(seed+4, server_random.random_bytes, 28);
	memcpy(seed+32, client_random.gmt_unix_time, 4);
	memcpy(seed+36, client_random.random_bytes, 28);

	FLEA_CCALL(PRF(master_secret, 48, PRF_LABEL_KEY_EXPANSION, seed, sizeof(seed), 128, key_block));
	FLEA_THR_FIN_SEC_empty();
}

/**
	TODO: fragmentation
	Reads in the record - "Header Data" is copied to the struct fields and the data is copied to a new location
*/
flea_err_t THR_flea_tls__read_record(flea_tls_ctx_t* tls_ctx, flea_u8_t* buff, flea_u32_t buff_len, Record* record, RecordType record_type, flea_u32_t* bytes_left) {
	FLEA_THR_BEG_FUNC();
	flea_u32_t i = 0;
	record->record_type = record_type;

	if (record_type == RECORD_TYPE_PLAINTEXT)
	{
		if (buff_len < 5)
		{
			printf("Record too short!");
			FLEA_THROW("record length too short", FLEA_ERR_TLS_GENERIC);
		}

		record->content_type = buff[i++];

		record->version.major = buff[i++];
		record->version.minor = buff[i++];

		// TODO: have to allow several TLS versions, maybe use <, <=, >, >= instead of ==, !=
		if (record->version.minor != tls_ctx->version.minor && record->version.major != tls_ctx->version.major)
		{
			printf("Version mismatch!");
			FLEA_THROW("version mismatch", FLEA_ERR_TLS_GENERIC);
		}

		flea_u8_t *p = (flea_u8_t*) &record->length;
		p[1] = buff[i++];
		p[0] = buff[i++];


		// need more data?
		if (record->length > buff_len - i)
		{
			// TODO: READ MORE DATA
			printf("Record Fragmenting not yet supported!");
			FLEA_THROW("Not Yet Implemented", FLEA_ERR_TLS_GENERIC);
		}

		// everything else is the record content
		record->data = calloc(record->length, sizeof(flea_u8_t));
		memcpy(record->data, buff+i, sizeof(flea_u8_t)*record->length);
		i += record->length;

		//*bytes_left = buff_len - i;
		*bytes_left = *bytes_left - i;

		// TODO: support encrypted / authenticated record messages
	}
	FLEA_THR_FIN_SEC_empty();
}




flea_err_t read_handshake_message(Record* record, HandshakeMessage* handshake_msg) {
	FLEA_THR_BEG_FUNC();
	if (record->length < 4)
	{
		FLEA_THROW("length too small", FLEA_ERR_TLS_GENERIC);
	}

	handshake_msg->type = record->data[0];

	flea_u8_t *p = (flea_u8_t*)&handshake_msg->length;
	p[2] = record->data[1];
	p[1] = record->data[2];
	p[0] = record->data[3];

	if (handshake_msg->length < record->length-4) {
		FLEA_THROW("length incorrect", FLEA_ERR_TLS_GENERIC);
	}

	if (handshake_msg->length > record->length-4) {
		// TODO: indicate somehow that this record is missing X byte and the handshake message is continuing in the next record
		// TODO: Check if necessary or done before this is called
	}
	handshake_msg->data = calloc(record->length-4, sizeof(flea_u8_t));
	memcpy(handshake_msg->data, record->data+4, sizeof(flea_u8_t)*(record->length-4));
	FLEA_THR_FIN_SEC_empty();
}

/*
typedef struct {
	ProtocolVersion server_version;
	Random random;
	SessionID session_id;
	flea_u8_t* cipher_suites;
	flea_u16_t cipher_suites_length;
	CompressionMethod compression_method;
	flea_u8_t* extensions;	// 2^16 bytes
} ServerHello;
*/
flea_err_t THR_flea_tls__read_server_hello(flea_tls_ctx_t* tls_ctx, HandshakeMessage* handshake_msg, ServerHello* server_hello)
{
	FLEA_THR_BEG_FUNC();
	if (handshake_msg->length < 41) // min ServerHello length
	{
		FLEA_THROW("length too small", FLEA_ERR_TLS_GENERIC);
	}

	// keep track of length
	int length = 0;

	// read version
	server_hello->server_version.major = handshake_msg->data[length++];
	server_hello->server_version.minor = handshake_msg->data[length++];

	// TODO: in this part the client has to decide if he accepts the server's TLS version - implement negotiation
	if (server_hello->server_version.major != tls_ctx->version.major || server_hello->server_version.minor != tls_ctx->version.minor)
	{
		FLEA_THROW("version mismatch", FLEA_ERR_TLS_GENERIC);
	}

	// read random
	flea_u8_t* p = (flea_u8_t*)server_hello->random.gmt_unix_time;
	for (flea_u8_t i=0; i<4; i++)
	{
		p[i] = handshake_msg->data[length++];
	}
	p = server_hello->random.random_bytes;
	for (flea_u8_t i=0; i<28; i++)
	{
		p[i] = handshake_msg->data[length++];
	}

	// read session id length
	server_hello->session_id_length = handshake_msg->data[length++];
	if (server_hello->session_id_length > 0)
	{
		server_hello->session_id = calloc(server_hello->session_id_length, sizeof(flea_u8_t));
		p = (flea_u8_t*)server_hello->session_id;
		for (flea_u8_t i=0; i<server_hello->session_id_length; i++)
		{
			p[i] = handshake_msg->data[length++];
		}
		// TODO: NEED TO CHECK IF LENGTH STILL LONG ENOUGH
	}

	if (length + 3 > handshake_msg->length)
	{
		FLEA_THROW("length incorrect", FLEA_ERR_TLS_GENERIC);
	}

	// read cipher suites
	p = (flea_u8_t*)&server_hello->cipher_suite;
	p[0] = handshake_msg->data[length++];
	p[1] = handshake_msg->data[length++];

	// read compression method
	server_hello->compression_method = handshake_msg->data[length++];

	// TODO: parse extension
	// for now simply ignore them

	// update security parameters
	memcpy(tls_ctx->security_parameters->server_random.gmt_unix_time, server_hello->random.gmt_unix_time, sizeof(tls_ctx->security_parameters->server_random.gmt_unix_time));	// QUESTION: sizeof durch variablen (#define) ersetzen?
	memcpy(tls_ctx->security_parameters->server_random.random_bytes, server_hello->random.random_bytes, sizeof(tls_ctx->security_parameters->server_random.random_bytes));

	// client wants to resume connection and has provided a session id
	if (tls_ctx->session_id_len != 0)
	{
		if (tls_ctx->session_id_len == server_hello->session_id_length)
		{
			if (memcmp(tls_ctx->session_id, server_hello->session_id, tls_ctx->session_id_len) == 0)
			{
				tls_ctx->resumption = FLEA_TRUE;
			}
		}

	}
	memcpy(tls_ctx->session_id, server_hello->session_id, server_hello->session_id_length);

	FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_verify_cert_chain(flea_u8_t* tls_cert_chain__acu8, flea_u32_t length, flea_public_key_t *pubkey__t)
{
  FLEA_DECL_OBJ(cert_chain__t, flea_cert_chain_t);
  const flea_u8_t date_str[] = "170228200000Z";	// TODO: datumsfunktion aufrufen
  flea_gmt_time_t time__t;
  flea_bool_t first__b = FLEA_TRUE;
	flea_err_t err;
	const flea_u8_t *ptr = tls_cert_chain__acu8;
	flea_al_u16_t len = length;

	FLEA_THR_BEG_FUNC();

	while(len > 3)
	{
		FLEA_DECL_OBJ(ref__t, flea_x509_cert_ref_t);
		flea_u32_t new_len = ((flea_u32_t)ptr[0] << 16) | (ptr[1] << 8) | (ptr[2]);
		ptr += 3;
		len -= 3;
		if(new_len > len)
		{
			FLEA_THROW("invalid cert chain length", FLEA_ERR_INV_ARG);
		}
		FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&ref__t, ptr, new_len));
		ptr += new_len;
		len -= new_len;
		if(first__b)
		{
			FLEA_CCALL(THR_flea_cert_chain_t__ctor(&cert_chain__t, &ref__t));
			first__b = FLEA_FALSE;
		}
		else
		{
			FLEA_CCALL(THR_flea_cert_chain_t__add_cert_without_trust_status(&cert_chain__t, &ref__t));
		}
	}

	FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) -1, &time__t));



	// add trust anchor
	FLEA_DECL_OBJ(trust_ref__t, flea_x509_cert_ref_t);
	err = THR_flea_x509_cert_ref_t__ctor(&trust_ref__t, trust_anchor, sizeof(trust_anchor));
	err = THR_flea_cert_chain_t__add_trust_anchor_cert(&cert_chain__t, &trust_ref__t);

	/* TODO: check again if all correct */
	flea_cert_chain_t__disable_revocation_checking(&cert_chain__t);
	err = THR_flea_cert_chain__build_and_verify_cert_chain_and_create_pub_key(&cert_chain__t, &time__t, pubkey__t);

	if(err)
	{
		FLEA_THROW("failed to verify chain!", FLEA_ERR_CERT_PATH_NOT_FOUND);
	}

	FLEA_THR_FIN_SEC(
	   flea_cert_chain_t__dtor(&cert_chain__t);
	);
}


flea_err_t read_certificate(flea_tls_ctx_t* tls_ctx, HandshakeMessage* handshake_msg, Certificate* cert_message, flea_public_key_t* pubkey)
{
	FLEA_THR_BEG_FUNC();

	// TODO: do properly and read the 3 bytes in
	cert_message->certificate_list_length = handshake_msg->length - 3;

	cert_message->certificate_list = calloc(cert_message->certificate_list_length, sizeof(flea_u8_t));

	memcpy(cert_message->certificate_list, handshake_msg->data+3, cert_message->certificate_list_length);

	FLEA_CCALL(THR_verify_cert_chain(cert_message->certificate_list, cert_message->certificate_list_length, pubkey));

	FLEA_THR_FIN_SEC_empty();
}


/**
Variable-length vectors are defined by specifying a subrange of legal
   lengths, inclusively, using the notation <floor..ceiling>.  When
   these are encoded, the actual length precedes the vector's contents
   in the byte stream.
*/
void client_hello_to_bytes(flea_tls__client_hello_t* hello, flea_u8_t* bytes, flea_u32_t* length)
{
	flea_u16_t i=0;

	memcpy(bytes, &hello->client_version.major, sizeof(flea_u8_t));
	i += sizeof(flea_u8_t);
	memcpy(bytes+i, &hello->client_version.minor, sizeof(flea_u8_t));
	i += sizeof(flea_u8_t);

	memcpy(bytes+i, hello->random.gmt_unix_time, sizeof(flea_u32_t));
	i += sizeof(flea_u32_t);
	memcpy(bytes+i, hello->random.random_bytes, 28);
	i += 28;

	flea_bool_t session_id_greater_0 = FLEA_FALSE;
	for (flea_u8_t j=0; i<32; j++)
	{
		if (hello->session_id[j] != 0)
		{
			session_id_greater_0 = 1;
		}
	}
	if (session_id_greater_0 == FLEA_TRUE)
	{
		bytes[i++] = 32;
		memcpy(bytes+i, hello->session_id, 32);
		i += 32;
	}
	else
	{
		bytes[i++] = 0;
	}

	// cipher suites length
	flea_u8_t *p = (flea_u8_t*) &hello->cipher_suites_length;
	bytes[i++] = p[1];
	bytes[i++] = p[0];

	for (flea_u8_t j=0; j<hello->cipher_suites_length/2; j++)
	{
		bytes[i++] = hello->cipher_suites[2*j];
		bytes[i++] = hello->cipher_suites[2*j+1];
	}

	bytes[i++] = hello->compression_methods_length;
	for (flea_u8_t j=0; j<hello->compression_methods_length;j++) {
		bytes[i++] = hello->compression_methods[j];
	}

	*length = i;
}

void create_handshake_message(HandshakeType type, flea_u8_t *in, flea_u32_t length_in, flea_u8_t *out, flea_u32_t *length_out)
{
	flea_u32_t i=0;

	// set handshake type
	out[i++] = type;

	// set handshake length
	flea_u8_t *p = (flea_u8_t*)&length_in;
	out[i++] = p[2];
	out[i++] = p[1];
	out[i++] = p[0];

	// copy all data
	memcpy(out+i, in, length_in);
	i += length_in;

	*length_out = i;
}

void record_to_bytes(Record* record, flea_u8_t *bytes, flea_u16_t *length)
{
	flea_u16_t i=0;
	bytes[i++] = record->content_type;
	bytes[i++] = record->version.major;
	bytes[i++] = record->version.minor;

	if (record->length < 256)
	{
		bytes[i++] = 0;
		bytes[i++] = record->length;
	}
	else
	{
		// TODO replace with function in bin_utils.c

		flea_u8_t *p = (flea_u8_t*)&record->length;
		bytes[i++] = p[1];
		bytes[i++] = p[0];
		// i+=2

	}

	memcpy(bytes+i, record->data, record->length);
	i += record->length;

	*length = i;
}

void handshake_to_bytes(HandshakeMessage handshake, flea_u8_t *bytes, flea_u32_t *length)
{
	flea_u16_t i=0;
	bytes[i++] = handshake.type;

	// TODO replace with function in bin_utils.c
	flea_u8_t *p = (flea_u8_t*)&handshake.length;
	bytes[i++] = p[2];
	bytes[i++] = p[1];
	bytes[i++] = p[0];

	memcpy(bytes+i, handshake.data, handshake.length);
	i += handshake.length;

	*length = i;
}

void change_cipher_spec_to_bytes(ChangeCipherSpec ccs, flea_u8_t* bytes)
{
	bytes[0] = ccs.change_cipher_spec;
}

void print_client_hello(flea_tls__client_hello_t hello)
{
	printf("\nPrinting ClientHello Struct\n");
	printf("Protocol Version major, minor: %i, %i\n", hello.client_version.major, hello.client_version.minor);

	printf("Random: \n");
	printf("\n\tUnix time ");
	for (int i=0; i<4; i++)
	{
		printf("%02x ", hello.random.gmt_unix_time[i]);
	}
	printf("\n\trandom bytes ");
	for (int i=0; i<28; i++)
	{
		printf("%02x ", hello.random.random_bytes[i]);
	}
	printf("\nSessionID: \n");
	for (flea_u8_t i=0; i<hello.session_id_length; i++)
	{
		printf("%02x ", hello.session_id[i]);
	}

	printf("\nCipher Suites: ");
	for (flea_u8_t i=0; i<hello.cipher_suites_length/2; i+=2)
	{
		printf("(%02x, %02x) ", hello.cipher_suites[i], hello.cipher_suites[i+1]);
	}

	printf("\nCompression Methods: ");
	for (flea_u8_t i=0; i<hello.compression_methods_length; i++)
	{
		printf("%02x ", hello.compression_methods[i]);
	}
}

void print_server_hello(ServerHello hello)
{
	printf("\nPrinting ServerHello Struct\n");
	printf("Protocol Version major, minor: %i, %i\n", hello.server_version.major, hello.server_version.minor);

	printf("Random: \n");
	printf("\n\tUnix time ");
	for (int i=0; i<4; i++)
	{
		printf("%02x ", hello.random.gmt_unix_time[i]);
	}
	printf("\n\trandom bytes ");
	for (int i=0; i<28; i++)
	{
		printf("%02x ", hello.random.random_bytes[i]);
	}
	printf("\nSessionID: \n");
	for (flea_u8_t i=0; i<hello.session_id_length; i++)
	{
		printf("%02x ", hello.session_id[i]);
	}
	printf("\nCipher Suite: ");
	flea_u8_t* p = (flea_u8_t*)&hello.cipher_suite;
	printf("(%02x, %02x) ", p[0], p[1]);

	printf("\nCompression Method: ");
	printf("%02x ", hello.compression_method);
}



/**
   Implementation note: Public-key-encrypted data is represented as an
   opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
   PreMasterSecret in a ClientKeyExchange is preceded by two length
   bytes.

   These bytes are redundant in the case of RSA because the
   EncryptedPreMasterSecret is the only data in the ClientKeyExchange
   and its length can therefore be unambiguously determined
*/
flea_err_t THR_flea_tls__create_client_key_exchange(flea_tls_ctx_t* tls_ctx, flea_public_key_t* pubkey, flea_tls__client_key_ex_t* key_ex)
{
	FLEA_THR_BEG_FUNC();
	flea_u8_t premaster_secret[48];

	premaster_secret[0] = 3;
	premaster_secret[1] = 3;
	key_ex->algorithm = KEY_EXCHANGE_ALGORITHM_RSA;

	// random 46 bit
	flea_rng__randomize(premaster_secret+2, 46);

	tls_ctx->premaster_secret[0] = tls_ctx->version.major;
	tls_ctx->premaster_secret[1] = tls_ctx->version.minor;
	//flea_rng__randomize(tls_ctx->premaster_secret+2, 46);
	memcpy(tls_ctx->premaster_secret+2, premaster_secret+2, 46);

	memcpy(key_ex->premaster_secret, premaster_secret, 48);

	/**
		   RSA encryption is done using the RSAES-PKCS1-v1_5 encryption scheme
		   https://tools.ietf.org/html/rfc3447#section-7.2
	*/

	// pubkey->key_bit_size__u16
	flea_al_u16_t result_len = 256;
	flea_u8_t buf[256];
	//THR_flea_public_key_t__encrypt_message(*key__pt, pk_scheme_id__t, hash_id__t, message__pcu8, message_len__alu16, result__pu8, result_len__palu16);
	FLEA_CCALL(THR_flea_public_key_t__encrypt_message(pubkey, flea_rsa_pkcs1_v1_5_encr, 0, premaster_secret, sizeof(premaster_secret), buf, &result_len));

	key_ex->encrypted_premaster_secret = calloc(result_len, sizeof(flea_u8_t));
	memcpy(key_ex->encrypted_premaster_secret, buf, result_len);
	key_ex->encrypted_premaster_secret_length = result_len;
	FLEA_THR_FIN_SEC_empty();
}

void client_key_exchange_to_bytes(flea_tls__client_key_ex_t* key_ex, flea_u8_t *bytes, flea_u32_t* length)
{
	flea_u16_t i = 0;
	flea_u8_t *p = (flea_u8_t*) &key_ex->encrypted_premaster_secret_length;
	bytes[i++] = p[1];
	bytes[i++] = p[0];

	for (flea_u16_t j=0; j<key_ex->encrypted_premaster_secret_length; j++)
	{
		bytes[i++] = key_ex->encrypted_premaster_secret[j];
	}

	*length = i;
}

void finished_to_bytes(flea_tls__finished_t* finished, flea_u8_t* bytes, flea_u32_t* length)
{
	flea_u32_t i = 0;
	// NOT NEEDED? (according to guys on stackoverflow you have 3 bytes maybe they meant the 3 bytes from the handshake message itself????)
	/*flea_u8_t *p = (flea_u8_t*)&finished->verify_data_length;
	bytes[i++] = p[2];
	bytes[i++] = p[1];
	bytes[i++] = p[0];*/

	for (flea_u32_t j=0; j<finished->verify_data_length; j++)
	{
		bytes[i++] = finished->verify_data[j];
	}

	*length = i;
}

void create_hello_message(flea_tls_ctx_t* tls_ctx, flea_tls__client_hello_t* hello)	{
	hello->client_version.major = tls_ctx->version.major;
	hello->client_version.minor = tls_ctx->version.minor;

	// session ID empty => no resumption (new handshake negotiation)
	hello->session_id = calloc(tls_ctx->session_id_len, sizeof(flea_u8_t));
	memcpy(hello->session_id, tls_ctx->session_id, tls_ctx->session_id_len);

	memcpy(hello->random.gmt_unix_time, tls_ctx->security_parameters->client_random.gmt_unix_time, sizeof(tls_ctx->security_parameters->client_random.gmt_unix_time));	// QUESTION: sizeof durch variablen (#define) ersetzen?
	memcpy(hello->random.random_bytes, tls_ctx->security_parameters->client_random.random_bytes, sizeof(tls_ctx->security_parameters->client_random.random_bytes));

	// TODO: check if pointer assignment is ok or if memcpy is better
	hello->cipher_suites = tls_ctx->allowed_cipher_suites;
	hello->cipher_suites_length = tls_ctx->allowed_cipher_suites_len;

	hello->compression_methods = tls_ctx->security_parameters->compression_methods;
	hello->compression_methods_length = tls_ctx->security_parameters->compression_methods_len;
	memcpy(hello->compression_methods, tls_ctx->security_parameters->compression_methods, tls_ctx->security_parameters->compression_methods_len);
}

int create_socket() {
	int socket_fd;
    socket_fd = socket(AF_INET , SOCK_STREAM , 0);

    if (socket_fd == -1)
    {
        printf("Could not create socket");
    }
	return socket_fd;
}


void create_handshake(HandshakeMessage* handshake, flea_u8_t* data, flea_u32_t length, HandshakeType type) {
	handshake->type = type;
	handshake->length = length;

	handshake->data = calloc(length, sizeof(flea_u8_t));
	memcpy(handshake->data, data, length);
}




/**
struct {
   opaque IV[SecurityParameters.record_iv_length];
   block-ciphered struct {
	   opaque content[TLSCompressed.length];
	   opaque MAC[SecurityParameters.mac_length];
	   uint8 padding[GenericBlockCipher.padding_length];
	   uint8 padding_length;
   };
} GenericBlockCipher;

IV Size
   The amount of data needed to be generated for the initialization
   vector.  Zero for stream ciphers; equal to the block size for
   block ciphers (this is equal to
   SecurityParameters.record_iv_length).


   To generate the key material, compute

         key_block = PRF(SecurityParameters.master_secret,
                         "key expansion",
                         SecurityParameters.server_random +
                         SecurityParameters.client_random);

      until enough output has been generated.  Then, the key_block is
      partitioned as follows:

         client_write_MAC_key[SecurityParameters.mac_key_length]
         server_write_MAC_key[SecurityParameters.mac_key_length]
         client_write_key[SecurityParameters.enc_key_length]
         server_write_key[SecurityParameters.enc_key_length]
         client_write_IV[SecurityParameters.fixed_iv_length]
         server_write_IV[SecurityParameters.fixed_iv_length]



	Initialization Vector (IV)
      When a block cipher is used in CBC mode, the initialization vector
      is exclusive-ORed with the first plaintext block prior to
      encryption.

	  IV
         The Initialization Vector (IV) SHOULD be chosen at random, and
         MUST be unpredictable.  Note that in versions of TLS prior to 1.1,
         there was no IV field, and the last ciphertext block of the
         previous record (the "CBC residue") was used as the IV.  This was
         changed to prevent the attacks described in [CBCATT].  For block
         ciphers, the IV length is of length
         SecurityParameters.record_iv_length, which is equal to the
         SecurityParameters.block_size.

*/
flea_err_t THR_flea_tls__create_record(flea_tls_ctx_t* tls_ctx, Record* record, flea_u8_t* data, flea_u32_t length, ContentType content_type, RecordType record_type) {
	FLEA_THR_BEG_FUNC();

	if (tls_ctx->active_write_connection_state->cipher_suite->id == TLS_NULL_WITH_NULL_NULL)
	{
		record->record_type = RECORD_TYPE_PLAINTEXT;
	}
	else
	{
		record->record_type = RECORD_TYPE_CIPHERTEXT;
	}

	record->content_type = content_type;
	record->version.major = tls_ctx->version.major;
	record->version.minor = tls_ctx->version.minor;

	// TODO: have to implement compression ?
	// TODO: length max 2^14
	if (record->record_type == RECORD_TYPE_PLAINTEXT)
	{
		record->length = length;
		record->data = calloc(length, sizeof(flea_u8_t));
		memcpy(record->data, data, length);
	}
	// TODO: length max 2^14 + 2048
	else if (record->record_type == RECORD_TYPE_CIPHERTEXT)
	{
		/**
			HARDCODED FOR AES256 SHA256 CBC
		*/
		/*flea_u8_t iv_length = tls_ctx->active_write_connection_state->cipher_suite->iv_size;
		flea_u8_t mac_length = tls_ctx->active_write_connection_state->cipher_suite->mac_size;
		flea_u8_t mac_key_length = tls_ctx->active_write_connection_state->cipher_suite->mac_key_size;
		flea_u8_t enc_key_length = tls_ctx->active_write_connection_state->cipher_suite->enc_key_size;
		flea_u8_t mac[mac_length];
		flea_u8_t iv[iv_length];
		flea_u8_t block_length = tls_ctx->active_write_connection_state->cipher_suite->block_size;
		flea_u64_t sequence_number = tls_ctx->active_write_connection_state->sequence_number;

		flea_u8_t client_write_mac_key[mac_key_length];
		memcpy(client_write_mac_key, tls_ctx->active_write_connection_state->mac_key, mac_key_length);

		flea_u8_t client_write_key[enc_key_length];
		memcpy(client_write_key, tls_ctx->active_write_connection_state->enc_key, enc_key_length);
		*/

		flea_u8_t iv_length = 16;	// AES always has 16 byte IV / block size
		flea_u8_t mac_length = 32; 	// sha256
		flea_u8_t mac[mac_length];
		flea_u8_t iv[iv_length];
		flea_u8_t block_length = 16;
		flea_u64_t sequence_number = 0;	/** HARD CODED!!!! only true for finished message message */

		// create keys
		flea_u8_t client_write_mac_key[32]; // for aes256/Sha256
		flea_u8_t server_write_mac_key[32]; // for aes256/Sha256
		flea_u8_t client_write_key[32]; // for aes256/Sha256
		flea_u8_t server_write_key[32]; // for aes256/Sha256

		memcpy(client_write_mac_key, key_block, 32);
		memcpy(server_write_mac_key, key_block+32, 32);
		memcpy(client_write_key, key_block+64, 32);
		memcpy(server_write_key, key_block+96, 32);

		/*printf("CLIENT WRITE MAC KEY: ");
		for (flea_u8_t k=0; k<32; k++)
		{
			printf("%02x ", client_write_mac_key[k]);
		}
		printf("\n");*/

		// compute mac
		/*
			MAC(MAC_write_key, seq_num +
                            TLSCompressed.type +
                            TLSCompressed.version +
                            TLSCompressed.length +
                            TLSCompressed.fragment);
		*/
		// 8 + 1 + (1+1) + 2 + length
		flea_u8_t mac_data_length = 13+length;
		flea_u8_t mac_data[mac_data_length];
		memcpy(mac_data, &sequence_number, 8);
		mac_data[8] = CONTENT_TYPE_HANDSHAKE;
		mac_data[9] = 0x03;
		mac_data[10] = 0x03;
		mac_data[11] = 0x00;
		mac_data[12] = length;	// length is < 256 in this case but have to generalize it
		memcpy(mac_data+13, data, length);

  	FLEA_CCALL(THR_flea_mac__compute_mac(flea_hmac_sha256, client_write_mac_key, 32, mac_data, mac_data_length, mac, (flea_al_u8_t*)(&mac_length)));


		// compute IV ... TODO: xor with last plaintext block?
		flea_rng__randomize(iv, iv_length);

		// compute padding
		flea_u8_t padding_length = (block_length - (length + mac_length + 1) % block_length) % block_length + 1;	// +1 for padding_length entry
		flea_u8_t padding[padding_length];
		flea_dtl_t input_output_len = length + padding_length + mac_length;
		flea_u8_t padded_data[input_output_len];
		for (flea_u8_t k=0; k<padding_length; k++)
		{
			padding[k] = padding_length - 1;	// account for padding_length entry again
		}
		memcpy(padded_data, data, length);
		memcpy(padded_data+length, mac, mac_length);
		memcpy(padded_data+length+mac_length, padding, padding_length);

		// compute encryption
		flea_u8_t encrypted[input_output_len];
		FLEA_CCALL(THR_flea_cbc_mode__encrypt_data(flea_aes256, client_write_key, 32, iv, iv_length, encrypted, padded_data, input_output_len));

		record->length = input_output_len+iv_length;
		record->data = calloc(input_output_len+iv_length, sizeof(flea_u8_t));
		memcpy(record->data, iv, iv_length);
		memcpy(record->data+iv_length, encrypted, input_output_len);
	}

	FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_tls__create_connection_params(flea_tls_ctx_t* tls_ctx, flea_tls__connection_state_t* connection_state,
	flea_tls__cipher_suite_t* cipher_suite, flea_bool_t writing_state)
{
	FLEA_THR_BEG_FUNC();

	connection_state->cipher_suite = cipher_suite;
	connection_state->compression_method = NO_COMPRESSION;
	connection_state->sequence_number = 0;
	flea_u8_t key_block2[128];	// max size for key_block in TLS 1.2
	connection_state->mac_key = calloc(connection_state->cipher_suite->mac_key_size, sizeof(flea_u8_t));
	connection_state->enc_key = calloc(connection_state->cipher_suite->enc_key_size, sizeof(flea_u8_t));
	generate_key_block_2(tls_ctx, key_block2);


	if (writing_state == FLEA_TRUE)
	{
	 	if (tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
		{
			memcpy(connection_state->mac_key, key_block2, connection_state->cipher_suite->mac_key_size);
			memcpy(connection_state->enc_key, key_block2+2*connection_state->cipher_suite->mac_key_size, connection_state->cipher_suite->enc_key_size);
		}
	}
	// TODO: !! implement other cases !!

	FLEA_THR_FIN_SEC_empty();

}



/** master_secret = PRF(pre_master_secret, "master secret",
		  ClientHello.random + ServerHello.random)
		  [0..47];
*/
flea_err_t create_master_secret(Random client_hello_random, Random server_hello_random, flea_u8_t* pre_master_secret, flea_u8_t* master_secret_res)
{
	FLEA_THR_BEG_FUNC();
	flea_u8_t random_seed[64];
	memcpy(random_seed, &client_hello_random.gmt_unix_time, 4);
	memcpy(random_seed+4, &client_hello_random.random_bytes, 28);	// TODO: this works?!?!?!?! pointer on pointer?
	memcpy(random_seed+32, &server_hello_random.gmt_unix_time, 4);
	memcpy(random_seed+36, &server_hello_random.random_bytes, 28);
	/*memcpy(random_seed, &server_hello_random.gmt_unix_time, 4);
	memcpy(random_seed+4, &server_hello_random.random_bytes, 28);
	memcpy(random_seed+32, &client_hello_random.gmt_unix_time, 4);
	memcpy(random_seed+36, &client_hello_random.random_bytes, 28);*/

	// pre_master_secret is 48 bytes, master_secret is desired to be 48 bytes
	FLEA_CCALL(PRF(pre_master_secret, 48, PRF_LABEL_MASTER_SECRET, random_seed, 64, 48, master_secret_res));
	FLEA_THR_FIN_SEC_empty();
}

/*
typedef struct {
  flea_u8_t* verify_data;
  flea_u16_t verify_data_length;	// 12 for all cipher suites defined in TLS 1.2 - RFC 5246
} Finished;

PRF(master_secret, finished_label, Hash(handshake_messages))
		[0..verify_data_length-1];
*/
flea_err_t create_finished(flea_u8_t* messages_hash , flea_u8_t master_secret[48], flea_tls__finished_t *finished_message) {
	FLEA_THR_BEG_FUNC();
	finished_message->verify_data_length = 12;	// 12 octets for all cipher suites defined in RFC 5246
	finished_message->verify_data = calloc(finished_message->verify_data_length, sizeof(flea_u8_t));

	FLEA_CCALL(PRF(master_secret, 48, PRF_LABEL_CLIENT_FINISHED, messages_hash, 32, finished_message->verify_data_length, finished_message->verify_data));
	FLEA_THR_FIN_SEC_empty();
}

// TODO: configurable parameters
flea_err_t flea_tls_ctx_t__ctor(flea_tls_ctx_t* ctx, flea_u8_t* session_id, flea_u8_t session_id_len) {
	FLEA_THR_BEG_FUNC();
	ctx->security_parameters = calloc(1, sizeof(flea_tls__security_parameters_t));

	/* specify connection end */
	ctx->security_parameters->connection_end = FLEA_TLS_CLIENT;

	/* set TLS version */
	ctx->version.minor = 0x03;
	ctx->version.major = 0x03;

	/* set cipher suite values */
	flea_u8_t TLS_RSA_WITH_AES_256_CBC_SHA256[] = { 0x00, 0x3D };

	ctx->allowed_cipher_suites = calloc(2, sizeof(flea_u8_t));
	memcpy(ctx->allowed_cipher_suites, TLS_RSA_WITH_AES_256_CBC_SHA256, 2);
	ctx->allowed_cipher_suites_len = 2;

    // CipherSuite TLS_NULL_WITH_NULL_NULL = { 0x00,0x00 };
	ctx->selected_cipher_suite[0] = 0x00;
	ctx->selected_cipher_suite[1] = 0x00;

	/* set SessionID */
	if (session_id_len > 32)
	{
		printf("max session id length: 32");
		FLEA_THROW("session id too large", FLEA_ERR_TLS_GENERIC);
	}
	memcpy(&ctx->session_id, session_id, session_id_len);
	ctx->session_id_len = session_id_len;

	/* set client_random */
	flea_rng__randomize(ctx->security_parameters->client_random.gmt_unix_time, 4);	// TODO: check RFC for correct implementation - actual time?
	flea_rng__randomize(ctx->security_parameters->client_random.random_bytes, 28);

	/* set compression methods  */
	ctx->security_parameters->compression_methods = calloc(1, sizeof(flea_u8_t));
	ctx->security_parameters->compression_methods[0] = NO_COMPRESSION;
	ctx->security_parameters->compression_methods_len = 1;

	ctx->resumption = FLEA_FALSE;

	ctx->premaster_secret = calloc(256, sizeof(flea_u8_t));



	ctx->pending_read_connection_state = calloc(1, sizeof(flea_tls__connection_state_t));
	ctx->pending_write_connection_state = calloc(1, sizeof(flea_tls__connection_state_t));
	ctx->active_read_connection_state = calloc(1, sizeof(flea_tls__connection_state_t));
	ctx->active_write_connection_state = calloc(1, sizeof(flea_tls__connection_state_t));
	ctx->active_read_connection_state->cipher_suite = &cipher_suites[0];	// set TLS_NULL_WITH_NULL_NULL
	ctx->active_write_connection_state->cipher_suite = &cipher_suites[0];

	FLEA_THR_FIN_SEC_empty();
}

// TODO: instead of socket_fd use something else
flea_err_t THR_flea_tls__receive(int socket_fd, flea_u8_t* buff, flea_u32_t buff_size, flea_u32_t* res_len) {
	FLEA_THR_BEG_FUNC();
	flea_s32_t res_tmp;	// need temporarily signed variable for recv() result
	res_tmp = recv(socket_fd, buff, buff_size, 0);
	if (res_tmp < 0) {
		FLEA_THROW("recv err", FLEA_ERR_TLS_GENERIC);	// TODO change error
	}
	*res_len = res_tmp;
	FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send(int socket_fd, flea_u8_t* buff, flea_u32_t buff_size) {
	FLEA_THR_BEG_FUNC();
	if (send(socket_fd, buff, buff_size, 0) < 0)
	{
		FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
	}
	FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_handshake_message(flea_tls_ctx_t* tls_ctx, flea_hash_ctx_t* hash_ctx, HandshakeType type, flea_u8_t* msg_bytes, flea_u32_t msg_bytes_len, int socket_fd) {
	FLEA_THR_BEG_FUNC();

	// create handshake message
	flea_u8_t handshake_bytes[16384]; // TODO: max length for handshake is 2^24 = 16777216
	flea_u32_t handshake_bytes_len;
	create_handshake_message(type, msg_bytes, msg_bytes_len, handshake_bytes, &handshake_bytes_len);

	// create record
	Record record;
	flea_u8_t record_bytes[16384];
	flea_u16_t record_bytes_len;
	THR_flea_tls__create_record(tls_ctx, &record, handshake_bytes, handshake_bytes_len, CONTENT_TYPE_HANDSHAKE, RECORD_TYPE_PLAINTEXT);	// TODO: can be something else than PLAINTEXT
	record_to_bytes(&record, record_bytes, &record_bytes_len);

	// send record
	if (send(socket_fd, record_bytes, record_bytes_len, 0) < 0)
	{
		printf("send failed\n");
		FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
	}

	// add handshake message to Hash
	FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, handshake_bytes, handshake_bytes_len));

	FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_tls__send_change_cipher_spec(flea_tls_ctx_t* tls_ctx, flea_hash_ctx_t* hash_ctx, int socket_fd)
{
	FLEA_THR_BEG_FUNC();

	Record change_cipher_spec_record;
	flea_u8_t change_cipher_spec_bytes[1] = {1};
	THR_flea_tls__create_record(tls_ctx, &change_cipher_spec_record, change_cipher_spec_bytes, 1, CONTENT_TYPE_CHANGE_CIPHER_SPEC, RECORD_TYPE_PLAINTEXT);

	flea_u8_t change_cipher_spec_record_bytes[16384];
	flea_u16_t change_cipher_spec_record_length=0;
	record_to_bytes(&change_cipher_spec_record, change_cipher_spec_record_bytes, &change_cipher_spec_record_length);

	if (send(socket_fd, change_cipher_spec_record_bytes, change_cipher_spec_record_length, 0) < 0)
	{
		printf("send failed\n");
		FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
	}

	FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_finished(flea_tls_ctx_t* tls_ctx, flea_hash_ctx_t* hash_ctx, int socket_fd)
{
	FLEA_THR_BEG_FUNC();

	// compute hash over handshake messages so far and create struct
	flea_tls__finished_t finished;
	flea_u8_t messages_hash[32];
	FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx, messages_hash));
	FLEA_CCALL(create_finished(messages_hash, tls_ctx->security_parameters->master_secret, &finished));

	// transform struct to bytes
	flea_u8_t finished_bytes[16384];
	flea_u32_t finished_bytes_len;
	finished_to_bytes(&finished, finished_bytes, &finished_bytes_len);

	// create handshake message
	flea_u8_t handshake_bytes[16384]; // TODO: max length for handshake is 2^24 = 16777216
	flea_u32_t handshake_bytes_len;
	create_handshake_message(HANDSHAKE_TYPE_FINISHED, finished_bytes, finished_bytes_len, handshake_bytes, &handshake_bytes_len);

	// create record
	Record record;
	flea_u8_t record_bytes[16384];
	flea_u16_t record_bytes_len;
	THR_flea_tls__create_record(tls_ctx, &record, handshake_bytes, handshake_bytes_len, CONTENT_TYPE_HANDSHAKE, RECORD_TYPE_CIPHERTEXT);	// TODO: can be something else than PLAINTEXT
	record_to_bytes(&record, record_bytes, &record_bytes_len);

	// send record
	if (send(socket_fd, record_bytes, record_bytes_len, 0) < 0)
	{
		printf("send failed\n");
		FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
	}

	// add handshake message to Hash
	//FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, handshake_bytes, handshake_bytes_len));

	FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_client_hello(flea_tls_ctx_t* tls_ctx, flea_hash_ctx_t* hash_ctx, int socket_fd)
{
	FLEA_THR_BEG_FUNC();

	flea_tls__client_hello_t client_hello;
	create_hello_message(tls_ctx, &client_hello);

	// transform struct to bytes
	flea_u8_t client_hello_bytes[16384];
	flea_u32_t client_hello_bytes_len;	// 24 bit
	client_hello_to_bytes(&client_hello, client_hello_bytes, &client_hello_bytes_len);

	//FLEA_CCALL(THR_flea_tls__send_handshake_message(tls_ctx, hash_ctx, HANDSHAKE_TYPE_CLIENT_HELLO, client_hello_bytes, client_hello_bytes_len, socket_fd));

	// create handshake message
	flea_u8_t handshake_bytes[16384]; // TODO: max length for handshake is 2^24 = 16777216
	flea_u32_t handshake_bytes_len;
	create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, client_hello_bytes, client_hello_bytes_len, handshake_bytes, &handshake_bytes_len);

	// create record
	Record record;
	flea_u8_t record_bytes[16384];
	flea_u16_t record_bytes_len;
	THR_flea_tls__create_record(tls_ctx, &record, handshake_bytes, handshake_bytes_len, CONTENT_TYPE_HANDSHAKE, RECORD_TYPE_PLAINTEXT);	// TODO: can be something else than PLAINTEXT
	record_to_bytes(&record, record_bytes, &record_bytes_len);

	// send record
	if (send(socket_fd, record_bytes, record_bytes_len, 0) < 0)
	{
		printf("send failed\n");
		FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
	}

	// add random to tls_ctx
	memcpy(tls_ctx->security_parameters->client_random.gmt_unix_time, client_hello.random.gmt_unix_time, sizeof(tls_ctx->security_parameters->client_random.gmt_unix_time));
	memcpy(tls_ctx->security_parameters->client_random.random_bytes, client_hello.random.random_bytes, sizeof(tls_ctx->security_parameters->client_random.random_bytes));

	// add handshake message to Hash
	FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, handshake_bytes, handshake_bytes_len));

	FLEA_THR_FIN_SEC_empty();
}

// send_client_key_exchange
flea_err_t THR_flea_tls__send_client_key_exchange(flea_tls_ctx_t* tls_ctx, flea_hash_ctx_t* hash_ctx, flea_public_key_t* pubkey, int socket_fd)
{
	FLEA_THR_BEG_FUNC();

	flea_tls__client_key_ex_t client_key_ex;
	THR_flea_tls__create_client_key_exchange(tls_ctx, pubkey, &client_key_ex);

	// transform struct to bytes
	flea_u8_t client_key_ex_bytes[16384];
	flea_u32_t client_key_ex_bytes_len;
	client_key_exchange_to_bytes(&client_key_ex, client_key_ex_bytes, &client_key_ex_bytes_len);

	// create handshake message
	flea_u8_t handshake_bytes[16384]; // TODO: max length for handshake is 2^24 = 16777216
	flea_u32_t handshake_bytes_len;
	create_handshake_message(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, client_key_ex_bytes, client_key_ex_bytes_len, handshake_bytes, &handshake_bytes_len);

	// create record
	Record record;
	flea_u8_t record_bytes[16384];
	flea_u16_t record_bytes_len;
	THR_flea_tls__create_record(tls_ctx, &record, handshake_bytes, handshake_bytes_len, CONTENT_TYPE_HANDSHAKE, RECORD_TYPE_PLAINTEXT);	// TODO: can be something else than PLAINTEXT
	record_to_bytes(&record, record_bytes, &record_bytes_len);

	// send record
	if (send(socket_fd, record_bytes, record_bytes_len, 0) < 0)
	{
		printf("send failed\n");
		FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
	}

	// add secrets to tls_ctx
	memcpy(tls_ctx->premaster_secret, client_key_ex.premaster_secret, 256); // TODO: variable size depending on key ex method

	// add handshake message to Hash
	FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, handshake_bytes, handshake_bytes_len));

	FLEA_THR_FIN_SEC_empty();
}

typedef struct {
	flea_u8_t* read_buff;
	flea_u32_t read_buff_len;
	flea_u32_t bytes_left;
	flea_u32_t bytes_read;
	flea_bool_t connection_closed;
} flea_tls__read_state_t;

void flea_tls__read_state_ctor(flea_tls__read_state_t* state) {
	state->read_buff = calloc(16384, sizeof(flea_u8_t));
	state->read_buff_len = 0;
	state->bytes_left = 0;
	state->bytes_read = 0;
	state->connection_closed = FLEA_FALSE;
}

flea_err_t THR_flea_tls__read_next_record(flea_tls_ctx_t* tls_ctx, Record* record, RecordType record_type, int socket_fd, flea_tls__read_state_t* state) {
	FLEA_THR_BEG_FUNC();

	// When no bytes are left we have to read new data from the network
	if (state->bytes_left == 0)
	{
		FLEA_CCALL(THR_flea_tls__receive(socket_fd, state->read_buff, 16384, &state->read_buff_len));
		state->bytes_left = state->read_buff_len;
		state->bytes_read = 0;
		if (state->read_buff_len == 0)
		{
			state->connection_closed = FLEA_TRUE;
			return FLEA_ERR_FINE;
		}
	}

	// else we read the next record
	FLEA_CCALL(THR_flea_tls__read_record(tls_ctx, state->read_buff+state->bytes_read, state->read_buff_len, record, record_type, &state->bytes_left));
	state->bytes_read = state->read_buff_len - state->bytes_left;

	FLEA_THR_FIN_SEC_empty();
}


typedef enum {
	FLEA_TLS_HANDSHAKE_EXPECT_NONE 					= 0x0, // zero <=> client needs to send his "second round"
	FLEA_TLS_HANDSHAKE_EXPECT_HELLO_REQUEST			= 0x1,
	FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO 			= 0x2,
	FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO 			= 0x4,
	FLEA_TLS_HANDSHAKE_EXPECT_NEW_SESSION_TICKET	= 0x8,
	FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE			= 0x10,
	FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE	= 0x20,
	FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST	= 0x40,
	FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE		= 0x80,
	FLEA_TLS_HANDSHAKE_EXPECT_f	= 0x100,
	FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE	= 0x200,
	FLEA_TLS_HANDSHAKE_EXPECT_FINISHED				= 0x400,
	FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC	= 0x800
} flea_tls__expect_handshake_type_t;


typedef struct {
	flea_u16_t expected_messages;
	flea_bool_t finished;
	flea_bool_t initialized;
	flea_bool_t send_client_cert;
} flea_tls__handshake_state_t;

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state)
{
	state->expected_messages = 0;
	state->finished = FLEA_FALSE;
	state->initialized = FLEA_FALSE;
	state->send_client_cert = FLEA_FALSE;
}


flea_err_t THR_flea_tls__client_handshake(int socket_fd, flea_tls_ctx_t* tls_ctx)
{
	FLEA_THR_BEG_FUNC();

	// define and init state
	flea_tls__handshake_state_t handshake_state;
	flea_tls__handshake_state_ctor(&handshake_state);
	flea_tls__read_state_t read_state;
	flea_tls__read_state_ctor(&read_state);
	flea_hash_ctx_t hash_ctx;
	THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256);	// TODO: initialize properly

	flea_public_key_t pubkey; // TODO: -> tls_ctx

	// received records and handshakes for processing the current state
	Record recv_record;
	HandshakeMessage recv_handshake;


	while (1) {

		// initialize handshake by sending CLIENT_HELLO
		if (handshake_state.initialized == FLEA_FALSE)
		{
			// send client hello
			THR_flea_tls__send_client_hello(tls_ctx, &hash_ctx, socket_fd);

			handshake_state.initialized = FLEA_TRUE;
			handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO;
		}

		/*
				1) read next Record
				2) if it's Alert: handle it
				   if it's Handshake Message or Change Cipher Spec Message: process it if it's among the expected_messages
		*/


		/*
			read next record
		*/
		if (handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_NONE)
		{
			// TODO: record type argument has to be removed because it's determined by the current connection state in tls_ctx
			FLEA_CCALL(THR_flea_tls__read_next_record(tls_ctx, &recv_record, RECORD_TYPE_PLAINTEXT, socket_fd,  &read_state));
			if (read_state.connection_closed == FLEA_TRUE)
			{
				printf("peer closed connection\n");
				break;
			}

			if (recv_record.content_type == CONTENT_TYPE_HANDSHAKE)
			{
				FLEA_CCALL(read_handshake_message(&recv_record, &recv_handshake));

				// update hash for all incoming handshake messages
				// TODO: only include messages sent AFTER ClientHello. At the moment it could include HelloRequest received before sending HelloRequest
				FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx, recv_record.data, recv_record.length));
			}
			else if (recv_record.content_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
			{
				if (handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
				{
					FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
				}
				else
				{
					handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;
					// TODO: verify that change cipher spec message is valid (?)

					/*
					 	Enable encryption parameters for server messages
					*/



					continue;
				}
			}
			else if (recv_record.content_type == CONTENT_TYPE_ALERT)
			{
				// TODO: handle alert message properly
				FLEA_THROW("Received unhandled alert", FLEA_ERR_TLS_GENERIC);
			}
			else
			{
				FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
			}
		}
		// We don't expect another message so it's our turn to continue
		else
		{
			if (handshake_state.send_client_cert == FLEA_TRUE)
			{
				// TODO: send certificate message
			}

			FLEA_CCALL(THR_flea_tls__send_client_key_exchange(tls_ctx, &hash_ctx, &pubkey, socket_fd));

			FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx, &hash_ctx, socket_fd));

			/*
				Enable encryption for outgoing messages
			*/

			// TODO: key_block_2 != key_block zu diesem zeitpunkt. Später in read_record gibt key_block2 das gleiche Ergebnis
			THR_flea_tls__create_connection_params(tls_ctx, tls_ctx->pending_write_connection_state, &cipher_suites[1], FLEA_TRUE);

			// make pending state active
			// TODO: call destructor active write state
			tls_ctx->active_write_connection_state = tls_ctx->pending_write_connection_state;
			// TODO: call constructor on pending write state

			FLEA_CCALL(create_master_secret(tls_ctx->security_parameters->client_random, tls_ctx->security_parameters->server_random, tls_ctx->premaster_secret, tls_ctx->security_parameters->master_secret));
			FLEA_CCALL(generate_key_block(tls_ctx->security_parameters->master_secret, tls_ctx->security_parameters->client_random, tls_ctx->security_parameters->server_random));

			FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &hash_ctx, socket_fd));

			printf("sent finished\n");

			handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
			continue;

		}


		if (handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO)
		{
			if (recv_handshake.type == HANDSHAKE_TYPE_SERVER_HELLO)
			{
				ServerHello server_hello; // TODO: don't need this
				FLEA_CCALL(THR_flea_tls__read_server_hello(tls_ctx, &recv_handshake, &server_hello));

				handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE
													| FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
													| FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
													| FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
				continue;
			}
			else
			{
				FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
			}
		}


		if (handshake_state.expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
		{
			if (recv_handshake.type == HANDSHAKE_TYPE_CERTIFICATE)
			{
				Certificate certificate_message; // TODO: don't need this
				read_certificate(tls_ctx, &recv_handshake, &certificate_message, &pubkey);
				tls_ctx->server_pubkey = pubkey;
				continue;
			}
			handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
												| FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
												| FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
		}

		// TODO: include here: FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE and FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST

		if (handshake_state.expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE)
		{
			if (recv_handshake.type == HANDSHAKE_TYPE_SERVER_HELLO_DONE)
			{
				handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
				// TODO: verify server hello done (?)
				continue;
			}
		}

		if (handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
		{
			if (recv_record.content_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
			{
				// TODO: process
				handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;
			}
			else
			{
				FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
			}
		}

		if (handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
		{
			if (recv_handshake.type == HANDSHAKE_TYPE_FINISHED)
			{
				// TODO: process
				printf("Handshake completed!\n");
				break;
			}
			else
			{
				FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
			}
		}
	}
	FLEA_THR_FIN_SEC_empty();
}


// TODO: socket generisch halten: send/recv funktionen function pointer
int flea_tls_connection()
{
	int socket_fd;
    struct sockaddr_in addr;

	socket_fd = create_socket();

	memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons( 4444 );
    /*addr.sin_addr.s_addr = inet_addr("31.15.64.162");
    addr.sin_family = AF_INET;
    addr.sin_port = htons( 443 );*/

	FLEA_THR_BEG_FUNC();

    if (connect(socket_fd , (struct sockaddr *)&addr , sizeof(addr)) < 0)
    {
		addr.sin_port = htons(4445);
		if (connect(socket_fd , (struct sockaddr *)&addr , sizeof(addr)) < 0)
		{
        	printf("connect error\n");
        	FLEA_THROW("Something went wrong!", FLEA_ERR_TLS_GENERIC);
		}
    }

	flea_tls_ctx_t tls_ctx;
	FLEA_CCALL(flea_tls_ctx_t__ctor(&tls_ctx, NULL, 0));

	flea_err_t err = THR_flea_tls__client_handshake(socket_fd, &tls_ctx);
	//flea_err_t err = flea_tls_handshake(socket_fd, &tls_ctx);

	// TODO: dtor

	if (err != FLEA_ERR_FINE) {
		FLEA_THROW("Something went wrong!", FLEA_ERR_TLS_GENERIC);
	}

	close (socket_fd);
    FLEA_THR_FIN_SEC_empty();
}
