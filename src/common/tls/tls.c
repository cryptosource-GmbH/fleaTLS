/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/tls.h"

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include<arpa/inet.h> //inet_addr

/*
   enum {
       hello_request(0), client_hello(1), server_hello(2),
       certificate(11), server_key_exchange (12),
       certificate_request(13), server_hello_done(14),
       certificate_verify(15), client_key_exchange(16),
       finished(20)
       (255)
   } HandshakeType;

   struct {
       HandshakeType msg_type;
       uint24 length;
       select (HandshakeType) {
           case hello_request:       HelloRequest;
           case client_hello:        ClientHello;
           case server_hello:        ServerHello;
           case certificate:         Certificate;
           case server_key_exchange: ServerKeyExchange;
           case certificate_request: CertificateRequest;
           case server_hello_done:   ServerHelloDone;
           case certificate_verify:  CertificateVerify;
           case client_key_exchange: ClientKeyExchange;
           case finished:            Finished;
       } body;
   } Handshake;
*/

typedef enum {
	HANDSHAKE_TYPE_HELLO_REQUEST = 0, 
	HANDSHAKE_TYPE_CLIENT_HELLO = 1 
		/*server_hello(2),
       certificate(11), server_key_exchange (12),
       certificate_request(13), server_hello_done(14),
       certificate_verify(15), client_key_exchange(16),
       finished(20)
       (255)*/
   } HandshakeType;


typedef enum { 
	 RECORD_TYPE_CHANGE_CIPHER_SPEC=20,
	 RECORD_TYPE_ALERT=21,
	 RECORD_TYPE_HANDSHAKE=22,
	 RECORD_TYPE_APPLICATION_DATA=23
} RecordType;

typedef struct {
	flea_u8_t major;
	flea_u8_t minor;
} ProtocolVersion;

typedef struct {
	RecordType record_type;
	ProtocolVersion version;
	flea_u16_t length;
	flea_u8_t *data;
} Record;


typedef struct {
	flea_u32_t gmt_unix_time;
	flea_u8_t random_bytes[28];
} Random;

typedef flea_u32_t SessionID;	// 32 bits

typedef enum { 
	NO_COMPRESSION=0, 
	COMPRESSION=255 
} CompressionMethod;

// TODO: Extensions

typedef struct {
	ProtocolVersion client_version;
	Random random;
	SessionID session_id;
	flea_u8_t* cipher_suites;
	flea_u16_t num_cipher_suites;
	CompressionMethod compression_methods;
	/*select (extensions_present) {
	  case false:
		  struct {};
	  case true:
		  Extension extensions<0..2^16-1>;
	};*/
} ClientHello;

/**
Variable-length vectors are defined by specifying a subrange of legal
   lengths, inclusively, using the notation <floor..ceiling>.  When
   these are encoded, the actual length precedes the vector's contents
   in the byte stream.
*/
void client_hello_to_bytes(ClientHello hello, flea_u8_t* bytes, flea_u16_t* length)
{
	flea_u16_t i=0;

	memcpy(bytes, &hello.client_version.minor, sizeof(flea_u8_t));
	i += sizeof(flea_u8_t);
	memcpy(bytes+i, &hello.client_version.major, sizeof(flea_u8_t));
	i += sizeof(flea_u8_t);

	memcpy(bytes+i, &hello.random.gmt_unix_time, sizeof(flea_u32_t));
	i += sizeof(flea_u32_t);
	memcpy(bytes+i, hello.random.random_bytes, 28);
	i += 28;

	if (hello.session_id != 0)
	{
		bytes[i++] = sizeof(SessionID);
		memcpy(bytes+i, hello.session_id, sizeof(SessionID));
		i += sizeof(SessionID);
	}
	else
	{
		bytes[i++] = 0;
	}

	// cipher suites length
	flea_u16_t len_ciphersuites = hello.num_cipher_suites * 2; 
	flea_u8_t *p = (flea_u8_t*) &len_ciphersuites;
	bytes[i++] = p[1];
	bytes[i++] = p[0];

	for (flea_u8_t j=0; j<hello.num_cipher_suites; j++)
	{
		bytes[i++] = hello.cipher_suites[2*j];
		bytes[i++] = hello.cipher_suites[2*j+1];
	}

	bytes[i++] = 1;
	bytes[i++] = hello.compression_methods;

	*length = i;
}

void create_handshake_message(HandshakeType type, flea_u8_t *in, flea_u32_t length_in, flea_u8_t *out, flea_u32_t *length_out) 
{
	flea_u8_t i=0;

	out[i++] = type;
	
	flea_u8_t *p = (flea_u8_t*)&length_in;
	out[i++] = p[2];
	out[i++] = p[1];
	out[i++] = p[0];

	memcpy(out+i, in, length_in);
	i += length_in;

	*length_out = i;
}

void record_to_bytes(Record record, flea_u8_t *bytes, flea_u8_t *length)
{
	flea_u16_t i=0;
	bytes[i++] = record.record_type;
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


void print_hello(ClientHello hello) 
{
	printf("\nPrinting Hello Struct\n");
	printf("Protocol Version major, minor: %i, %i\n", hello.client_version.major, hello.client_version.minor);

	printf("Random: \n");
	printf("\tUnix Time %i", hello.random.gmt_unix_time);
	printf("\n\trandom bytes ");
	for (int i=0; i<28; i++)
	{
		printf("%02x ", hello.random.random_bytes[i]);
	}
	printf("\nSessionID: %u\n", hello.session_id);
	printf("Cipher Suites: ");
	for (int i=0; i<hello.num_cipher_suites; i+=2)
	{
		printf("(%02x, %02x) ", hello.cipher_suites[i], hello.cipher_suites[i+1]);
	}
	printf("\nCompression Method: %i\n\n", hello.compression_methods);
	
	
}

ClientHello create_hello_message()	{
	flea_u8_t random_bytes[28] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};

	flea_u8_t gmt_unix_time[4] = {0x00, 0x01, 0x02, 0x03};
	flea_u8_t TLS_RSA_WITH_AES_256_CBC_SHA256[] = { 0x00, 0x3D };
	flea_u8_t* cipher_suites = malloc(2);	// TODO deallocate
	
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
	hello.num_cipher_suites = 1;
		
	hello.compression_methods = NO_COMPRESSION;

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


int flea_tls_handshake(int socket_fd)
{
	flea_u8_t reply[16384];

	ClientHello hello = create_hello_message();
	print_hello(hello);

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
	printf("Created Handshake Message of length %i:\n", handshake_length);
	for (flea_u16_t i=0; i<handshake_length; i++)
	{
		printf("%02x ", handshake_message[i]);
	}
	printf("\n\n");


	Record hello_record;
	hello_record.record_type = RECORD_TYPE_HANDSHAKE;
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


	/*flea_u8_t test_send[] = {0x16, 0x03, 0x03, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x5b, 0x03, 0x03, 0x54, 0x9a, 0xab, 0x72, 0x98,
0x65, 0x11, 0x2f, 0xda, 0x9e, 0xcf, 0xc9, 0xdb, 0x6c, 0xbd, 0x4b, 0x4c, 0x56, 0x4b, 0x0c, 0xa5,
0x68, 0x2b, 0xaa, 0x60, 0x1f, 0x38, 0x66, 0xe7, 0x87, 0x46, 0xb2, 0x00, 0x00, 0x2e, 0x00, 0x39,
0x00, 0x38, 0x00, 0x35, 0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2f,
0x00, 0x9a, 0x00, 0x99, 0x00, 0x96, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09,
0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x04,
0x00, 0x23, 0x00, 0x00};
	printf("Test Message %i:\n", sizeof(test_send));
	for (flea_u16_t i=0; i<sizeof(test_send); i++)
	{
		printf("%02x ", test_send[i]);
	}
	printf("\n\n");

	if (send(socket_fd, test_send, sizeof(test_send), 0) < 0)
		printf("send failed\n");
*/
	if (send(socket_fd, record_message, record_length, 0) < 0)
		printf("send failed\n");

	printf("receiving ...\n");
	
	flea_u32_t recv_bytes;
	while(1)
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
 
    if (connect(socket_fd , (struct sockaddr *)&addr , sizeof(addr)) < 0)
    {
        printf("connect error\n");
        return 1;
    }

	flea_tls_handshake(socket_fd);     
	
    printf("Connected\n");
	close (socket_fd);
    return 0;
}
