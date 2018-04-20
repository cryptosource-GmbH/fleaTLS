/*! \page pageAe Authenticated Encryption in fleaTLS
 *
\section secAe Authenticated Encryption

fleaTLS support the following authenticated encryptions schemes

- GCM/AES
- EAX/AES

Both schemes support all three AES key lengths and are referenced by the enumeration #flea_ae_id_e.

The authenticated encryption schemes can be either applied directly to array of input data or computed iteratively.

An Authenticated Encryption scheme receives as input for encryption or decryption function

- the key,
- the plaintext or ciphertext,
- associated data: this data is authenticated but not encrypted,
- and a nonce: the nonce value needs to be different for each encryption operation using the same key.

The associated data may be of length zero.

<table>
<tr> <th> AE scheme <th> key length <th> nonce length (bytes) <th> tag length (bytes) </tr>
<tr> <td> <a href= "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">GCM</a>				<td> as the key length of the underlying cipher <td> any  <td> 1 ... 16 </tr>
<tr> <td> <a href="http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf">EAX</a>				<td> as the key length of the underlying cipher <td> any  <td> 1 ... 16  </tr>
</table>
It is recommended to use the maximally possible tag length of 16 bytes.


\subsection secAeDirect Direct Authenticated Encryption Computation

The direct computation of a an authenticated encryption operation is achieved by the functions #THR_flea_ae__encrypt() and  #THR_flea_ae__decrypt(). The output has the same length as the input.

\subsection secAeIter Iterative Authenticated Encryption Computation

Iterative computation of the encrypted authentication operations is done using the flea_ae_ctx_t type.
The first function to call is certainly always #THR_flea_ae_ctx_t__ctor(): the created object can be used either for encryption or decryption. This is decided by either calling only encrypt or only decrypt functions on this object.
The following is the subsequent call sequence for encryption:

- #THR_flea_ae_ctx_t__update_encryption(): this function can be called multiple times with portions of input / output data. The ouput data (encrypted data) will always have the same size as the input data.
- #THR_flea_ae_ctx_t__final_encryption(): this function is called when all input data has been processed. It creates the authentication tag.

The call sequence for decryption is:

- #THR_flea_ae_ctx_t__update_decryption():  this function can be called multiple times with portions of input / output data. The authentication tag value is also simply input to this function. The output data (decrypted data) may be smaller than the input data. Accordingly, it returns the length of the actually generated output data.
- #THR_flea_ae_ctx_t__final_decryption(): this function verifies the tag. It returns #FLEA_ERR_INV_MAC if the verification fails. Any other error returned by this function must also be considered an authentication failure.

Note that the concrete tag length choice is specified in the ctor call. The "finalize" functions then always produces tags of the requested size.

The following code taken from the file <code>test/src/common/test_ae.c</code> gives an example.

\snippet test_ae.c ae_update_example
*/
