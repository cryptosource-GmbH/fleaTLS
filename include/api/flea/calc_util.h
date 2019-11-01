/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


#ifndef _flea_calc_util__H_
#define _flea_calc_util__H_


/**
 * Determine the maximum of two values
 */
#define FLEA_MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * Determine the maximum of three values
 */
#define FLEA_MAX3(a, b, c) FLEA_MAX((a), FLEA_MAX((b), (c)))

/**
 * Determine the maximum of four values
 */
#define FLEA_MAX4(a, b, c, d) FLEA_MAX(FLEA_MAX((a), (b)), FLEA_MAX((c), (d)))

/**
 * Determine the maximum of five values
 */
#define FLEA_MAX5(a, b, c, d, e) FLEA_MAX(FLEA_MAX((a), (b)), FLEA_MAX3((c), (d), (e)))

/**
 * Determine the minimum of two values
 */
#define FLEA_MIN(a, b) ((a) > (b) ? (b) : (a))

/**
 * Determine the minimum of three values
 */
#define FLEA_MIN3(a, b, c) FLEA_MIN((a), FLEA_MIN((b), (c)))

/**
 * Determine the minimum of four values
 */
#define FLEA_MIN4(a, b, c, d) FLEA_MIN(FLEA_MIN((a), (b)), FLEA_MIN((c), (d)))

/**
 * Determine the word length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_WORD_LEN_FROM_BIT_LEN(__a) (FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(__a)))

/**
 * Determine the word length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(__a) (((__a) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t))

/**
 * Determine the byte length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(__a) (((__a) + 7) / 8)

/**
 * Determine the u32 length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_U32_LEN_FROM_BIT_LEN(__a) (((__a) + 8 * sizeof(flea_u32_t) - 1) / (8 * sizeof(flea_u32_t)))

#endif /* h-guard */
