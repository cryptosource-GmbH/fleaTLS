/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/tls.h"

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

#include "flea/pubkey.h"
#include "flea/asn1_date.h"
#include "flea/cert_chain.h"
#include "flea/ber_dec.h"
#include "flea/mac.h"
#include "flea/rng.h"
#include "flea/hash.h"


flea_u8_t trust_anchor[] = {0x30, 0x82, 0x03, 0x7f, 0x30, 0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xfe, 0x12, 0x36, 0x42, 0xa1, 0xb6, 0xf7, 0x11, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xa5, 0x70, 0x42, 0x71, 0x64, 0xdf, 0xfa, 0x98, 0x43, 0x8a, 0x13, 0x5f, 0xe3, 0x7d, 0xed, 0x27, 0xff, 0x52, 0x3a, 0x6b, 0x7f, 0x0f, 0xd6, 0x80, 0xaa, 0xfd, 0x2e, 0xf9, 0xb7, 0xcf, 0x6b, 0x46, 0x72, 0x91, 0x95, 0x39, 0x44, 0xc1, 0xbf, 0x69, 0x9e, 0x65, 0xab, 0xbd, 0xa7, 0xe6, 0x3c, 0xfd, 0x12, 0x09, 0xa6, 0xda, 0x1e, 0xf4, 0x12, 0x9b, 0x0d, 0xd6, 0x5c, 0x6c, 0xdf, 0x64, 0x77, 0xfe, 0x35, 0x2d, 0xd9, 0xad, 0x99, 0xc1, 0x47, 0x31, 0xef, 0x95, 0x23, 0x38, 0x48, 0xd7, 0xa6, 0x84, 0x69, 0x6c, 0x4d, 0x37, 0xe8, 0x29, 0xd3, 0xb4, 0x68, 0x03, 0x19, 0xdc, 0xb1, 0xd1, 0xfd, 0xfb, 0x97, 0x61, 0x50, 0xe7, 0x2a, 0xa0, 0xfd, 0x7c, 0x8f, 0x51, 0x88, 0x0b, 0x5d, 0x74, 0xce, 0xb6, 0xa5, 0x65, 0x53, 0xb2, 0x0d, 0xdf, 0xb5, 0x7a, 0xe1, 0x3c, 0x98, 0x6e, 0x29, 0xa7, 0x90, 0x75, 0x13, 0xac, 0x22, 0x92, 0xdb, 0xe6, 0x8c, 0x6f, 0x32, 0xa7, 0x42, 0xa4, 0xa4, 0x5c, 0x04, 0xdb, 0x04, 0x95, 0x34, 0x13, 0xe0, 0xa1, 0x47, 0x00, 0x21, 0xf6, 0xa1, 0xa7, 0xaa, 0x0e, 0x97, 0xc5, 0x2b, 0x64, 0x00, 0x74, 0xdd, 0x57, 0xe3, 0x03, 0xe0, 0xb8, 0xc5, 0x4e, 0xe3, 0x3e, 0xf0, 0x33, 0x7d, 0x5e, 0x82, 0xda, 0xaa, 0x04, 0x0d, 0xdc, 0x80, 0x14, 0xaf, 0x30, 0x10, 0x9c, 0x5b, 0xb8, 0xd2, 0xb6, 0x76, 0x6c, 0x10, 0x27, 0xfd, 0x6e, 0xaa, 0xc2, 0x70, 0x7e, 0x0d, 0x37, 0x2c, 0x28, 0x81, 0x26, 0xc8, 0xeb, 0x7c, 0x4b, 0x8f, 0xda, 0x7b, 0x02, 0xb0, 0x51, 0x92, 0x3d, 0x3d, 0x5e, 0x53, 0xfa, 0xcb, 0x43, 0x4f, 0xef, 0x1e, 0x61, 0xe5, 0xb9, 0x2c, 0x08, 0x77, 0xff, 0x65, 0x77, 0x13, 0x4d, 0xd4, 0xcb, 0x2e, 0x7f, 0x9d, 0xe2, 0x1a, 0xc3, 0x19, 0x84, 0xb1, 0x52, 0x9d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7b, 0x18, 0xad, 0x25, 0x86, 0x17, 0x93, 0x93, 0xcb, 0x01, 0xe1, 0x07, 0xce, 0xfa, 0x37, 0x96, 0x5f, 0x17, 0x95, 0x1d, 0x76, 0xf3, 0x04, 0x36, 0x81, 0x64, 0x78, 0x2a, 0xc2, 0xcc, 0xbd, 0x77, 0xf7, 0x59, 0xeb, 0x9a, 0xf7, 0xb3, 0xfc, 0x1a, 0x30, 0xfe, 0x6f, 0x6e, 0x02, 0xc6, 0x2d, 0x4d, 0x79, 0x25, 0xaf, 0x98, 0xb4, 0xab, 0x3e, 0x25, 0xfc, 0xef, 0x98, 0x26, 0x0f, 0x6a, 0x0a, 0x74, 0x5b, 0x4f, 0x3a, 0x6c, 0xd6, 0x42, 0x56, 0xd9, 0x25, 0x0a, 0x1e, 0x3a, 0x4c, 0x74, 0xe9, 0x28, 0xcf, 0x7d, 0xe9, 0x48, 0xdc, 0xd6, 0xf4, 0x23, 0xf7, 0x2e, 0xc9, 0x50, 0xb7, 0xad, 0x22, 0x9b, 0xdf, 0x60, 0xcf, 0x2f, 0x4b, 0x98, 0x79, 0x3d, 0x56, 0xf0, 0x03, 0xfd, 0xe1, 0x61, 0x12, 0xed, 0x44, 0xe8, 0x22, 0xce, 0x4d, 0x41, 0xe7, 0xd4, 0x9c, 0xf9, 0x12, 0x57, 0x12, 0xb0, 0x20, 0xb3, 0xfa, 0xf5, 0x09, 0x8b, 0xc6, 0x38, 0xc2, 0x31, 0x41, 0xe8, 0xf3, 0x1c, 0x9a, 0xb7, 0x87, 0x73, 0x64, 0x29, 0xc5, 0x0f, 0x8e, 0x2d, 0x80, 0xbd, 0x54, 0x16, 0x6d, 0xc2, 0xcd, 0x5f, 0x0c, 0x12, 0xe0, 0xd2, 0x6b, 0xce, 0x99, 0x53, 0x7b, 0xa8, 0x38, 0x4e, 0x17, 0xea, 0xc1, 0x70, 0x9b, 0x33, 0x39, 0xc2, 0x83, 0x11, 0xba, 0xbd, 0x9b, 0x79, 0x09, 0xc5, 0x01, 0xea, 0x2d, 0xc6, 0x56, 0xf2, 0x9a, 0x14, 0x68, 0x37, 0xb2, 0x28, 0xb0, 0x60, 0xf0, 0xc6, 0xf4, 0xa6, 0x1e, 0xeb, 0x2b, 0x1d, 0x0e, 0xa0, 0x58, 0xfc, 0xd8, 0x2c, 0x01, 0xa3, 0xcf, 0xae, 0xa8, 0x3b, 0x49, 0x9e, 0xad, 0x51, 0xe7, 0x08, 0x65, 0x8c, 0x5c, 0x33, 0x54, 0x04, 0x14, 0x48, 0xf1, 0x79, 0xab, 0x33, 0xf5, 0xd4, 0xe0, 0xef, 0x1a, 0x62, 0x13, 0x48, 0xda, 0x52, 0x3e, 0x02, 0x8f, 0x64, 0xba, 0x8e, 0xf1, 0x88};

typedef enum { FINISHED_LABEL_CLIENT, FINISHED_LABEL_SERVER } FinishedLabel;


typedef enum {
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


typedef enum {
	 CONTENT_TYPE_CHANGE_CIPHER_SPEC=20,
	 CONTENT_TYPE_ALERT=21,
	 CONTENT_TYPE_HANDSHAKE=22,
	 CONTENT_TYPE_APPLICATION_DATA=23,
	 CONTENT_TYPE_HEARTBEAT=24
} ContentType;

typedef enum {
	 RECORD_TYPE_PLAINTEXT,
	 RECORD_TYPE_CIPHERTEXT,
	 RECORD_TYPE_COMPRESSED,
} RecordType;

typedef struct {
	flea_u8_t major;
	flea_u8_t minor;
} ProtocolVersion;

typedef struct {
	RecordType record_type;
	ContentType content_type;
	ProtocolVersion version;
	flea_u16_t length;
	flea_u8_t *data;
} Record;


typedef struct {
	flea_u32_t gmt_unix_time;
	flea_u8_t random_bytes[28];
} Random;

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
	ProtocolVersion client_version;
	Random random;
	flea_u8_t* session_id;
	flea_u8_t session_id_length;
	flea_u8_t* cipher_suites;
	flea_u16_t cipher_suites_length;
	CompressionMethod* compression_methods;
	flea_u8_t compression_methods_length;
	flea_u8_t* extensions;	// 2^16 bytes
} ClientHello;

typedef struct {
	ProtocolVersion server_version;
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
	flea_u8_t EncryptedPreMasterSecret[48];
	flea_u8_t* ClientDiffieHellmanPublic;
	flea_u16_t length;
} ClientKeyExchange;

typedef enum {CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC = 1} CHANGE_CIPHER_SPEC_TYPE;

typedef struct {
	CHANGE_CIPHER_SPEC_TYPE change_cipher_spec;
} ChangeCipherSpec;


typedef struct {
  flea_u8_t* verify_data;
  flea_u16_t verify_data_length;	// 12 for all cipher suites defined in TLS 1.2 - RFC 5246
} Finished;

/**
	ServerHelloDone: no content, no struct needed
*/

/**
	TODO: Expected to take exactly one record layer message. One TCP packet can contain several record layer messages. need to handle this.
	TODO: Could also be fragmented!
	=> leave this function as is but add a function that takes care of this before passing values on to this function
*/
void read_record_message(flea_u8_t* bytes, flea_u32_t length, Record* record, RecordType record_type) {


	if (record_type == RECORD_TYPE_PLAINTEXT)
	{
		if (length < 5)
		{
			return;	// TODO: error handling
		}

		record->content_type = bytes[0];
		// TODO: check content type. Maybe "expected_content_type"
		/*if (record->content_type < CONTENT_TYPE_CHANGE_CIPHER_SPEC || record->content_type > CONTENT_TYPE_HEARTBEAT)
		{
			return; // TODO: error handling
		}*/


		record->version.major = bytes[1];
		record->version.minor = bytes[2];
		if (record->version.minor != 0x03 && record->version.major != 3)
		{
			return; // TODO: error handling
		}

		flea_u8_t *p = (flea_u8_t*) &record->length;
		p[0] = bytes[4];
		p[1] = bytes[3];
		if (record->length != length - 5)
		{
			return;	// TODO: error handling
		}

		// set length to length of the content
		length = length-5;

		// everything else should be plaintext data from now on
		record->data = calloc(length, sizeof(flea_u8_t));
		memcpy(record->data, bytes+5, sizeof(flea_u8_t)*length);
	}
}



void read_handshake_message(Record* record, HandshakeMessage* handshake_msg) {
	if (record->length < 4)
	{
		return; // TODO: error handling
	}

	handshake_msg->type = record->data[0];

	flea_u8_t *p = (flea_u8_t*)&handshake_msg->length;
	p[2] = record->data[1];
	p[1] = record->data[2];
	p[0] = record->data[3];

	if (handshake_msg->length < record->length-4) {
		return; // TODO: error handling
	}

	if (handshake_msg->length > record->length-4) {
		// TODO: indicate somehow that this record is missing X byte and the handshake message is continuing in the next record
	}
	handshake_msg->data = calloc(record->length-4, sizeof(flea_u8_t));
	memcpy(handshake_msg->data, record->data+4, sizeof(flea_u8_t)*(record->length-4));
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
void read_server_hello(HandshakeMessage* handshake_msg, ServerHello* server_hello_msg)
{
	if (handshake_msg->length < 41) // min ServerHello length
	{
		return; // TODO: error handling
	}

	// keep track of length
	int length = 0;

	// read version
	server_hello_msg->server_version.major = handshake_msg->data[length++];
	server_hello_msg->server_version.minor = handshake_msg->data[length++];
	if (server_hello_msg->server_version.major != 0x03 || server_hello_msg->server_version.minor != 0x03)
	{
		return; // TODO: error handling
	}

	// read random
	flea_u8_t* p = (flea_u8_t*)&server_hello_msg->random.gmt_unix_time;
	for (flea_u8_t i=0; i<4; i++)
	{
		p[i] = handshake_msg->data[length++];
	}

	p = server_hello_msg->random.random_bytes;
	for (flea_u8_t i=0; i<28; i++)
	{
		p[i] = handshake_msg->data[length++];
	}

	// read session id length
	server_hello_msg->session_id_length = handshake_msg->data[length++];
	if (server_hello_msg->session_id_length > 0)
	{
		server_hello_msg->session_id = calloc(server_hello_msg->session_id_length, sizeof(flea_u8_t));
		p = (flea_u8_t*)server_hello_msg->session_id;
		for (flea_u8_t i=0; i<server_hello_msg->session_id_length; i++)
		{
			p[i] = handshake_msg->data[length++];
		}
		// TODO: NEED TO CHECK IF LENGTH STILL LONG ENOUGH
	}

	if (length + 3 > handshake_msg->length)
	{
		return; // TODO: error handling
	}

	// read cipher suites
	p = (flea_u8_t*)&server_hello_msg->cipher_suite;
	p[0] = handshake_msg->data[length++];
	p[1] = handshake_msg->data[length++];

	// read compression method
	server_hello_msg->compression_method = handshake_msg->data[length++];

	// TODO: parse extension
	// for now simply ignore them
}


/**
cert_chain.h:
	flea_err_t THR_flea_cert_chain_t__add_trust_anchor_cert(flea_cert_chain_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt);

	flea_err_t THR_flea_cert_chain__build_and_verify_cert_chain( flea_cert_chain_t *cert_chain__pt, const flea_gmt_time_t *time__pt);

	flea_err_t THR_flea_cert_chain__build_and_verify_cert_chain_and_create_pub_key( flea_cert_chain_t *cert_chain__pt, const flea_gmt_time_t *time__pt, flea_public_key_t *key_to_construct_mbn__pt);
*/

flea_err_t THR_verify_cert_chain(flea_u8_t* tls_cert_chain__acu8, flea_u32_t length, flea_public_key_t *pubkey__t)
{
  FLEA_DECL_OBJ(cert_chain__t, flea_cert_chain_t);
  const flea_u8_t date_str[] = "170228200000Z";
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
	err = THR_flea_cert_chain__build_and_verify_cert_chain_and_create_pub_key(&cert_chain__t, &time__t, pubkey__t);

	if(err)
	{
		FLEA_THROW("failed to verify chain!", FLEA_ERR_CERT_PATH_NOT_FOUND);
	}

	FLEA_THR_FIN_SEC(
	   flea_cert_chain_t__dtor(&cert_chain__t);
	);
}


void read_certificate(HandshakeMessage* handshake_msg, Certificate* cert_message, flea_public_key_t* pubkey)
{
	//cert_message->certificate_list_length = handshake_msg->length;
	flea_u8_t *p = (flea_u8_t*)&cert_message->certificate_list_length;
	p[2] = handshake_msg->data[0];
	p[1] = handshake_msg->data[1];
	p[0] = handshake_msg->data[2];

	cert_message->certificate_list = calloc(cert_message->certificate_list_length, sizeof(flea_u8_t));


	memcpy(cert_message->certificate_list, handshake_msg->data+3, cert_message->certificate_list_length);



	flea_err_t err = THR_verify_cert_chain(cert_message->certificate_list, cert_message->certificate_list_length, pubkey);

	/**

	test_cert_chain.c hat beispielcode zum decoden von certificate content

	*/
}


/**
Variable-length vectors are defined by specifying a subrange of legal
   lengths, inclusively, using the notation <floor..ceiling>.  When
   these are encoded, the actual length precedes the vector's contents
   in the byte stream.
*/
void client_hello_to_bytes(ClientHello hello, flea_u8_t* bytes, flea_u16_t* length)
{
	flea_u16_t i=0;

	memcpy(bytes, &hello.client_version.major, sizeof(flea_u8_t));
	i += sizeof(flea_u8_t);
	memcpy(bytes+i, &hello.client_version.minor, sizeof(flea_u8_t));
	i += sizeof(flea_u8_t);

	memcpy(bytes+i, &hello.random.gmt_unix_time, sizeof(flea_u32_t));
	i += sizeof(flea_u32_t);
	memcpy(bytes+i, hello.random.random_bytes, 28);
	i += 28;

	int session_id_greater_0 = 0;
	for (flea_u8_t j=0; i<32; j++)
	{
		if (hello.session_id[j] != 0)
		{
			session_id_greater_0 = 1;
		}
	}
	if (session_id_greater_0)
	{
		bytes[i++] = 32;
		memcpy(bytes+i, hello.session_id, 32);
		i += 32;
	}
	else
	{
		bytes[i++] = 0;
	}

	// cipher suites length
	flea_u8_t *p = (flea_u8_t*) &hello.cipher_suites_length;
	bytes[i++] = p[1];
	bytes[i++] = p[0];

	for (flea_u8_t j=0; j<hello.cipher_suites_length/2; j++)
	{
		bytes[i++] = hello.cipher_suites[2*j];
		bytes[i++] = hello.cipher_suites[2*j+1];
	}

	bytes[i++] = hello.compression_methods_length;
	for (flea_u8_t j=0; j<hello.compression_methods_length;j++) {
		bytes[i++] = hello.compression_methods[j];
	}

	*length = i;
}

void create_handshake_message(HandshakeType type, flea_u8_t *in, flea_u32_t length_in, flea_u8_t *out, flea_u32_t *length_out)
{
	flea_u8_t i=0;

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

flea_u32_t get_size_of_first_record(flea_u8_t* bytes, flea_u8_t length) {
	if (length < 5) {
		return; // TODO: error handling
	}
	if (bytes[0] != 16 && bytes[1] != 3 && bytes[2] != 3)
	{
		printf("ERROR in get_size_of_first_record: first 3 bytes(%02x, %02x, %02x) ", bytes[0], bytes[1], bytes[2]);
		// TODO: error handling
	}
	flea_u16_t size;
	flea_u8_t *p = (flea_u8_t*) &size;
	p[0] = bytes[4];
	p[1] = bytes[3];

	return size+5;
}

void record_to_bytes(Record record, flea_u8_t *bytes, flea_u8_t *length)
{
	flea_u16_t i=0;
	bytes[i++] = record.content_type;
	bytes[i++] = record.version.major;
	bytes[i++] = record.version.minor;

	if (record.length <= 256)
	{
		bytes[i++] = 0;
		bytes[i++] = record.length;
	}
	else
	{
		// TODO check if correct (byte order?)
		memcpy(bytes+i, &record.length, 2);
		i += 2;
	}

	memcpy(bytes+i, record.data, record.length);
	i += record.length;

	*length = i;
}

void handshake_to_bytes(HandshakeMessage handshake, flea_u8_t *bytes, flea_u32_t *length)
{
	flea_u16_t i=0;
	bytes[i++] = handshake.type;

	// TODO check if correct (byte order?)
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

void print_client_hello(ClientHello hello)
{
	printf("\nPrinting ClientHello Struct\n");
	printf("Protocol Version major, minor: %i, %i\n", hello.client_version.major, hello.client_version.minor);

	printf("Random: \n");
	printf("\tUnix Time %i", hello.random.gmt_unix_time);
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
	printf("\tUnix Time %i", hello.random.gmt_unix_time);
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
	TODO: real randomness

   Implementation note: Public-key-encrypted data is represented as an
   opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
   PreMasterSecret in a ClientKeyExchange is preceded by two length
   bytes.

   These bytes are redundant in the case of RSA because the
   EncryptedPreMasterSecret is the only data in the ClientKeyExchange
   and its length can therefore be unambiguously determined
*/
ClientKeyExchange create_client_key_exchange(flea_public_key_t* pubkey)
{
	ClientKeyExchange key_ex;
	flea_u8_t premaster_secret[48];

	key_ex.length = 48;

	premaster_secret[0] = 3;
	premaster_secret[1] = 3;
	key_ex.algorithm = KEY_EXCHANGE_ALGORITHM_RSA;

	// random 46 bit
	flea_rng__randomize(premaster_secret+2, 46);

	/**
		   RSA encryption is done using the RSAES-PKCS1-v1_5 encryption scheme
		   https://tools.ietf.org/html/rfc3447#section-7.2
	*/
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// TODO LENGTH OF ENCRYPTED SECRET IS NOT 48 it depends on KEY SIZE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	flea_al_u16_t result_len = 2000;
	flea_u8_t buf[2000];
	//THR_flea_public_key_t__encrypt_message(*key__pt, pk_scheme_id__t, hash_id__t, message__pcu8, message_len__alu16, result__pu8, result_len__palu16);
	flea_err_t err = THR_flea_public_key_t__encrypt_message(pubkey, flea_rsa_pkcs1_v1_5_encr, 0, &premaster_secret, sizeof(premaster_secret), buf, &result_len);

	return key_ex;
}

void client_key_exchange_to_bytes(ClientKeyExchange* key_ex, flea_u8_t *bytes)
{
	flea_u8_t *p = (flea_u8_t*) &key_ex->length;
	bytes[0] = p[1];
	bytes[1] = p[0];

	for (flea_u8_t i=0; i<48; i++)
	{
		bytes[i+2] = key_ex->EncryptedPreMasterSecret[i];
	}
}

ClientHello create_hello_message()	{
	flea_u8_t random_bytes[28] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};

	flea_u8_t gmt_unix_time[4] = {0x00, 0x01, 0x02, 0x03};
	flea_u8_t TLS_RSA_WITH_AES_256_CBC_SHA256[] = { 0x00, 0x3D };
	flea_u8_t* cipher_suites = calloc(2, sizeof(flea_u8_t));	// TODO deallocate

	ClientHello hello;
	memset(&hello, 0, sizeof(ClientHello));

	hello.client_version.major = 3;
	hello.client_version.minor = 3;

	// session ID empty => no resumption. TODO is 4 zero bytes == empty?
	hello.session_id = 0;

	memcpy(&hello.random.gmt_unix_time, gmt_unix_time, sizeof(gmt_unix_time));
	memcpy(hello.random.random_bytes, random_bytes, sizeof(random_bytes));

	memcpy(cipher_suites, TLS_RSA_WITH_AES_256_CBC_SHA256, sizeof(TLS_RSA_WITH_AES_256_CBC_SHA256));
	hello.cipher_suites = cipher_suites;
	hello.cipher_suites_length = 2;

	hello.compression_methods = calloc(1, sizeof(flea_u8_t));
	hello.compression_methods_length = 1;
	hello.compression_methods[0] = NO_COMPRESSION;

	return hello;
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

void create_record(Record* record, flea_u8_t* data, flea_u32_t length, ContentType content_type, RecordType record_type) {
	record->content_type = content_type;
	record->record_type = record_type;
	record->version.major = 3;
	record->version.minor = 3;
	record->length = length;

	record->data = calloc(length, sizeof(flea_u8_t));
	memcpy(record->data, data, length);
}



P_Hash(flea_u8_t* secret, flea_u16_t secret_length, flea_u8_t* seed, flea_u8_t seed_length, flea_u16_t length, flea_u8_t* data_out)
{
	flea_mac_ctx_t mac_ctx;
	flea_u8_t A[32];
	flea_u8_t A2[32];
	flea_u8_t tmp_input[32 + seed_length];	//* TODO: check if this is ok. In C99 yes but can I rely on variable length arrays? */
	flea_u8_t tmp_output[32];

	// A(0) = seed
	memcpy(A, seed, 32);

	// expand to length bytes
	flea_u16_t current_length = 0;
	flea_al_u8_t len;
	flea_err_t err;
	while (current_length < length)
	{
		// A(i) = HMAC_hash(secret, A(i-1))
		err = THR_flea_mac__compute_mac(flea_hmac_sha256, A, 32, secret, secret_length, A2, &len);
		memcpy(A, A2, 32);

		// calculate A(i) + seed
		memcpy(tmp_input, A, 32);
		memcpy(tmp_input+32, seed, seed_length);

		// + HMAC_hash(secret, A(i) + seed)
		// concatenate to the result
		err = THR_flea_mac__compute_mac(flea_hmac_sha256, tmp_input, 32, secret, secret_length, tmp_output, &len);
		if (current_length+32 < length)
		{
			memcpy(data_out+current_length, tmp_output, 32);
		}
		else
		{
			memcpy(data_out+current_length, tmp_output, length - current_length);
		}
		current_length += 32; 	// sha256 -> 32 bytes
	}
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
void PRF(flea_u8_t* secret, flea_u8_t secret_length, FinishedLabel label, flea_u8_t seed[32], flea_u16_t length, flea_u8_t* result) {
	/**
		TODO: no fixed sha256
	*/
	flea_u8_t client_finished[] = {99, 108, 105, 101, 110, 116, 032, 102, 105, 110, 105, 115, 104, 101, 100};

	switch (label) {
		case FINISHED_LABEL_CLIENT: P_Hash(secret, secret_length, client_finished, sizeof(client_finished), length, result); break;
	}
}

/*
typedef struct {
  flea_u8_t* verify_data;
  flea_u16_t verify_data_length;	// 12 for all cipher suites defined in TLS 1.2 - RFC 5246
} Finished;

PRF(master_secret, finished_label, Hash(handshake_messages))
		[0..verify_data_length-1];
*/
Finished create_finished(flea_u8_t* handshake_messages, flea_u32_t handshake_messages_len, flea_u8_t master_secret[48], Finished *finished_message) {
	finished_message->verify_data = calloc(96, sizeof(flea_u8_t));
	flea_err_t THR_flea_compute_hash(flea_hash_id_t id, const flea_u8_t* input, flea_dtl_t input_len, flea_u8_t* output, flea_al_u16_t output_len);

	flea_u8_t messages_hash[32];
	THR_flea_compute_hash(flea_sha256, handshake_messages, handshake_messages_len, messages_hash, 32);
	PRF(master_secret, 48, FINISHED_LABEL_CLIENT, messages_hash, 96, finished_message->verify_data);

	finished_message->verify_data_length = 96;
}

int flea_tls_handshake(int socket_fd)
{
	flea_u8_t secret[] = "test";
	flea_u8_t seed[32];
	flea_u8_t result[96];
	PRF(secret, sizeof(secret), FINISHED_LABEL_CLIENT, seed, 96, result);
	/**
	*/
	flea_u8_t reply[16384];

	flea_u8_t handshake_messages_concat[100000];
	flea_u32_t handshake_messages_concat_index = 0;

	ClientHello hello = create_hello_message();
	print_client_hello(hello);

	flea_u8_t hello_message[16384];
	flea_u16_t length;
	client_hello_to_bytes(hello, hello_message, &length);
	printf("Created ClientHello data of length %i:\n", length);
	for (flea_u16_t i=0; i<length; i++)
	{
		printf("%02x ", hello_message[i]);
	}
	printf("\n\n");

	flea_u8_t handshake_message[16384];
	flea_u32_t handshake_length;	// 24 bit
	create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, hello_message, length, handshake_message, &handshake_length);
	memcpy(handshake_messages_concat + handshake_messages_concat_index, handshake_message, handshake_length);
	handshake_messages_concat_index += handshake_length;

	printf("Created Handshake Message of length %i:\n", handshake_length);
	for (flea_u16_t i=0; i<handshake_length; i++)
	{
		printf("%02x ", handshake_message[i]);
	}
	printf("\n\n");


	Record hello_record;
	hello_record.content_type = CONTENT_TYPE_HANDSHAKE;
	hello_record.record_type = RECORD_TYPE_PLAINTEXT;
	hello_record.version.major = 3;
	hello_record.version.minor = 3;
	hello_record.length = handshake_length;
	hello_record.data = handshake_message;

	flea_u8_t record_message[16384];
	flea_u8_t record_length = 0;
	record_to_bytes(hello_record, record_message, &record_length);


	printf("Created Record ClientHello message of length %i:\n", record_length);
	for (flea_u16_t i=0; i<record_length; i++)
	{
		printf("%02x ", record_message[i]);
	}
	printf("\n\n");


	printf("sending HelloClient ...\n");
	if (send(socket_fd, record_message, record_length, 0) < 0)
		printf("send failed\n");

	printf("receiving ...\n");

	flea_u32_t recv_bytes;
	int handshake_initiated=0;
	while(!handshake_initiated)
	{
		recv_bytes = recv(socket_fd, reply, 16384, 0);
		if (recv_bytes < 0)
			printf("recv failed\n");

		printf("received message of length %i:\n", recv_bytes);
		for (flea_u16_t i=0; i<recv_bytes; i++)
		{
			printf("%02x ", reply[i]);
		}
		printf("\n");

		printf("Parsing Message:\n");
		Record record_message;
		HandshakeMessage handshake_message;
		ServerHello server_hello_message;
		Certificate certificate_message;
		flea_public_key_t pubkey;
		flea_u8_t handshake_messages_concat_tmp_bytes[16384];
		flea_u32_t handshake_messages_concat_tmp_length;

		flea_u32_t reply_index = 0;
		while (reply_index != recv_bytes)
		{
			memset(&record_message, 0, sizeof(Record));
			memset(&handshake_message, 0, sizeof(HandshakeMessage));

			flea_u32_t first_record_size = get_size_of_first_record(reply+reply_index, recv_bytes-reply_index);
			printf("\n\nrecord size %i\n\n", first_record_size);

			printf("Reading Record ...\n");
			read_record_message(reply+reply_index, first_record_size, &record_message, RECORD_TYPE_PLAINTEXT);

			printf("Reading HandshakeMessage ...\n");
			read_handshake_message(&record_message, &handshake_message);

			handshake_to_bytes(handshake_message, handshake_messages_concat_tmp_bytes, &handshake_messages_concat_tmp_length);
			memcpy(handshake_messages_concat + handshake_messages_concat_index, handshake_messages_concat_tmp_bytes, handshake_messages_concat_tmp_length);
			handshake_messages_concat_index += handshake_messages_concat_tmp_length;

			printf("Reading HandshakeMessage content...\n");
			printf("handshake_message.type: %i\n", handshake_message.type);
			if (handshake_message.type == HANDSHAKE_TYPE_SERVER_HELLO)
			{
				read_server_hello(&handshake_message, &server_hello_message);
				printf("Parsed ServerHello:\n");
				print_server_hello(server_hello_message);
			}
			else if(handshake_message.type == HANDSHAKE_TYPE_CERTIFICATE)
			{

				read_certificate(&handshake_message, &certificate_message, &pubkey);
				printf("\nParsed Certificate Message:\n");
			}
			else if(handshake_message.type == HANDSHAKE_TYPE_SERVER_HELLO_DONE)
			{
				printf("Parsed ServerHelloDone:\n");
				if (handshake_message.length != 0)
				{
					// ERROR
				}
				printf("sending ClientKeyExchange ...\n");

				flea_u8_t client_key_ex_bytes[48+2];
				ClientKeyExchange client_key_ex = create_client_key_exchange(&pubkey);
				client_key_exchange_to_bytes(&client_key_ex, client_key_ex_bytes);
				Record client_key_ex_record;
				HandshakeMessage client_key_ex_handshake;

				create_handshake(&client_key_ex_handshake, client_key_ex_bytes, 48+2, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE);
				flea_u8_t client_key_ex_handshake_bytes[16384];
				flea_u16_t client_key_ex_handshake_length;
				handshake_to_bytes(client_key_ex_handshake, client_key_ex_handshake_bytes, &client_key_ex_handshake_length);

				create_record(&client_key_ex_record, client_key_ex_handshake_bytes, client_key_ex_handshake_length, CONTENT_TYPE_HANDSHAKE, RECORD_TYPE_PLAINTEXT);
				flea_u8_t client_key_ex_record_bytes[16384];
				flea_u16_t client_key_ex_record_length;
				record_to_bytes(client_key_ex_record, client_key_ex_record_bytes, &client_key_ex_record_length);

					if (send(socket_fd, client_key_ex_record_bytes, client_key_ex_record_length, 0) < 0)
					printf("send failed\n");

				memcpy(handshake_messages_concat + handshake_messages_concat_index, client_key_ex_handshake_bytes, client_key_ex_handshake_length);
				handshake_messages_concat_index += client_key_ex_handshake_length;

				/** All Handshake Messages received/sent: now can compute hash */
				printf("\n CONCAT: \n");
				for (flea_u32_t k = 0; k<handshake_messages_concat_index; k++) {
					printf("%02x ", handshake_messages_concat[k]);
				}
				printf("\n");

				printf("sending ChangeCipherSpec ...\n");
				Record change_cipher_spec_record;

				flea_u8_t change_cipher_spec_bytes[1] = {1};
				create_record(&change_cipher_spec_record, change_cipher_spec_bytes, 1, CONTENT_TYPE_CHANGE_CIPHER_SPEC, RECORD_TYPE_PLAINTEXT);

				flea_u8_t change_cipher_spec_record_bytes[16384];
				flea_u16_t change_cipher_spec_record_length;
				record_to_bytes(change_cipher_spec_record, change_cipher_spec_record_bytes, &change_cipher_spec_record_length);

				if (send(socket_fd, change_cipher_spec_record_bytes, change_cipher_spec_record_length, 0) < 0)
					printf("send failed\n");

				/* Create Finished Message */
				Finished finished_message;
				//create_finished(handshake_messages_concat, handshake_messages_concat_index, master_secret, &finished_message);
			}
			else
			{
				printf("Message not recognized\n");
				exit(-1);
			}
			reply_index += first_record_size;

		}
	}
}



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

    if (connect(socket_fd , (struct sockaddr *)&addr , sizeof(addr)) < 0)
    {
		addr.sin_port = htons(4445);
		if (connect(socket_fd , (struct sockaddr *)&addr , sizeof(addr)) < 0)
		{
        	printf("connect error\n");
        	return 1;
		}
    }

	flea_tls_handshake(socket_fd);

    printf("Connected\n");
	close (socket_fd);
    return 0;
}
