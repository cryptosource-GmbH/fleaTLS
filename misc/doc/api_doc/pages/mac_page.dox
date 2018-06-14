/*! \page pageMac Message Authentication Codes
 *
\section secMac Message Authentication Codes

fleaTLS supports the following message authentication code (MAC) functions:

<table>
<tr> <th> MAC <th> key length (bytes) <th> recommended key lengths (bytes) <th> MAC length (bytes) </tr>
<tr> <td>  HMAC/MD5       <td> any                <td> 16 ... 64                      <td>  16 </tr>
<tr> <td>  HMAC/SHA-1		<td> any                <td> 20 ... 64											<td>  20 </tr>
<tr> <td>  HMAC/SHA-224		<td> any                <td> 28 ... 64											<td>  28 </tr>
<tr> <td>  HMAC/SHA-256		<td> any                <td> 32 ... 64											<td>  32 </tr>
<tr> <td>  HMAC/SHA-384     <td> any                <td> 48 ... 128											<td>  48 </tr>
<tr> <td>  HMAC/SHA-512     <td> any                <td> 64 ... 128											<td>  64 </tr>
<tr> <td>  CMAC/DES				<td> 8(*)									<td> N/A															<td> 8 </tr>
<tr> <td>  CMAC/DES-X				<td> 24(*)									<td>  N/A														<td> 8 </tr>
<tr> <td>  CMAC/3DES 2-key				<td> 16(*)									<td>N/A                               <td> 8 </tr>
<tr> <td>  CMAC/3DES 3-key				<td> 24(*)									<td>N/A															<td> 8 </tr>
<tr> <td>  CMAC/AES-128				<td> 16									<td> N/A															<td> 16 </tr>
<tr> <td>  CMAC/AES-192				<td> 24									<td> N/A														<td> 16 </tr>
<tr> <td>  CMAC/AES-254				<td> 32									<td> N/A														<td> 16 </tr>
</table>
(*) For all DES variants each key byte contains one unused bit in accordance with common practice.

The recommended minimal key lengths in the above table are in accordance with <a href="https://tools.ietf.org/html/rfc2104">RFC 2104</a>.

The MAC functions are referenced through the values of #flea_mac_id_e.

For the MAC generation and verification, the two different approaches that are explained in the following subsections are possible.

\subsection secMacDirect Direct MAC Computation

The generation and verification without a MAC context object can be done using the functions #THR_flea_mac__compute_mac() and #THR_flea_mac__verify_mac().

\subsection secMacIter Iterative MAC Computation

MACs can be computed iteratively on input data using an object of type #flea_mac_ctx_t.
The call sequence in this case is

- #THR_flea_mac_ctx_t__ctor()
- #THR_flea_mac_ctx_t__update(): potentially multiple calls to this function can be made
- Then the operation can be completed either by generating a MAC or verifying a MAC:
  - generate a MAC: #THR_flea_mac_ctx_t__final_compute()
  - verify a MAC: #THR_flea_mac_ctx_t__final_verify()

Note that it should be refrained from verifying a MAC by generating it and then comparing it to a received MAC within the application code, as this introduces timing side channels that potentially lead to vulnerabilities. fleaTLS uses a secure function for the MAC comparison internally.

The following code taken from the file <code>test/src/common/test_mac.c</code> shows an example for the MAC verification:

\snippet test_mac.c mac_update_example


*/
