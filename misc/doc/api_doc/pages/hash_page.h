/*! \page pageHash Hash Functions
 *
\section secHash Hash Functions

fleaTLS offers the following hash functions:

<table>
<tr> <th> Hash function <th> Output length (bytes) </tr>
<tr> <td> MD5           <td> 16 </tr>
<tr> <td> SHA-1					<td> 20 </tr>
<tr> <td> SHA-224				<td> 28 </tr>
<tr> <td> SHA-256       <td> 32 </tr>
<tr> <td> SHA-384			  <td> 48 </tr>
<tr> <td> SHA-512       <td> 64	</tr>
</table>

The correponding IDs are provided by the enumeration #flea_hash_id_e.

In order to compute the hash value of a message, two different approaches are possible.

\subsection secHashConv Direct Hash Computation

The functions #THR_flea_compute_hash() and #THR_flea_compute_hash_byte_vec() can be used to compute the hash value of an array in single function call.

\subsection secHashIter Iterative Hash Computation

Using a hash context object, hash computations can be carried out iteratively, as in the following example taken from <code>test/src/common/test_hash.c</code>.

\snippet test_hash.c hash_ctx_example

Note that the digest_buffer will receive the hash value of byte length as indicated by the function
<code>
flea_hash_ctx_t__get_output_length(&ctx) </code>.

*/
