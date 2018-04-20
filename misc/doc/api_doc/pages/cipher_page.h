/*! \page pageCipher Block Ciphers
 *
\section secCipher Block Ciphers

fleaTLS supports the following block ciphers

<table>
<tr> <th> Cipher <th> key length (bytes) <th> block size (bytes) </tr>
<tr> <td> DES <td> 8 (*)	<td> 8 </tr>
<tr> <td> DES-X <td> 24 (*)	<td> 8  </tr>
<tr> <td> TDES 2-key <td> 16 (*)  <td> 8 </tr>
<tr> <td> TDES 3-key <td> 24 (*)  <td> 8 </tr>
<tr> <td> AES-128        <td> 16  <td> 16 </tr>
<tr> <td> AES-192        <td> 24 <td> 16 </tr>
<tr> <td> AES-246        <td> 32 <td> 16 </tr>
</table>

(*) For all DES variants each key byte contains one unused bit in accordance with common practice.

Note that the raw DES cipher is insecure and included in fleaTLS only for compatibility reasons.

fleaTLS supports the use of block ciphers in the modes ECB, CBC and CTR.

\subsection secEcbMode ECB Mode

In order to use the ECB mode, an object of type #flea_ecb_mode_ctx_t has to be created using  the #THR_flea_ecb_mode_ctx_t__ctor() function. The #flea_cipher_dir_e argument specifies whether a context object for encryption or decryption shall be created. Then data can be portion-wise encrypted or decrypted using the function #THR_flea_ecb_ctx_t__crypt_data(). Each call must input data which is an integer multiple of the chosen cipher's block size.

\subsection secCbcMode CBC Mode

The setting up of a CBC context object of type #flea_cbc_mode_ctx_t is similar to that of an ECB context object. However, the CBC context object requires an additional initialization vector (IV) of the length of the cipher's block size. For CBC, the data must be input in portions being an integer multiple of the cipher's block size to the function #THR_flea_cbc_mode_ctx_t__crypt().

For the CBC mode, additionally the function #THR_flea_cbc_mode__crypt_data() is available, which allows for the encryption or decryption of data without the use of a context object.

\subsection secCtrMode CTR Mode

For CTR mode, an object of type #flea_ctr_mode_ctx_t can be set up using the function #THR_flea_ctr_mode_ctx_t__ctor(). This function takes a nonce value as input. The nonce value can have any length ranging 0 to the cipher's block length. The nonce becomes part of the counter block in such a way that the first byte of the nonce becomes the most significant byte of the counter block and the remaining bytes of the counter block are filled with zeroes. Given the nonce is shorter than the block size, this would result in a counter block of the following form:
<PRE>
nonce | 0... 0
             ^
             |
      incrementation
      starts here

</PRE>

When creating a CTR mode context type, the cipher direction (encryption / decryption) does not have to be specified, as both are actually the same operation in this mode. Accordingly, the function #flea_ctr_mode_ctx_t__crypt() has to be called in order to encrypt or decrypt portions of data. No restrictions apply to the length of the input.

Furthermore, the function #THR_flea_ctr_mode_crypt_data can be used to encrypt or decrypt data without the instantiation of a context object.
*/
