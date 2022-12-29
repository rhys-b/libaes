/* Author: Rhys Byers
 * Modified: 2022/09/25
 * 
 * This library contains functions allowing data to be encrypted according to
 * the AES128 specification.
 */
 

#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdint.h>
#include <stdbool.h>


/* Expand a 128-bit key into a 44-byte key schedule. */
void expand_key(uint32_t key[4], uint32_t schedule[44]);

/* Encrypts 128-bits of data using a caller-supplied key schedule. The
 * schedule can be obtained from the expand_key() function. */
void cipher(uint8_t data[16], uint32_t schedule[44]);

/* Decrypts 128-bits of data using the caller-supplied key schedule. The
 * schedule can be obtained from the expand_key() function, and is the same
 * for both encryption and decryption. */
void decipher(uint8_t data[16], uint32_t schedule[44]);

/* Used by the algorithm to rotate the 4 bytes of a 32-bit word.
 * [word] must point to the first byte of the word.
 * [byte_gap] must contain the gap between memory addresses of each of
 * the bytes (1 if the bytes are in a byte array).
 * [shift] contains the amount to shift by. A positive shift means a normal byte
 * is shifted to a higher address. Negative is the opposite. */
void rotate(uint8_t *word, uint8_t byte_gap, int8_t shift);

/* Used by the algorithm to substitute bytes. It uses the provided table to
 * substitue [size] bytes into [arr], based on their initial values. */
void substitute(uint8_t *arr, size_t size, const uint8_t *table);

/* Used by the algorithm for the shift rows step. Shifts the second row 1 byte,
 * the third 2 bytes, and the last row 3 bytes. A forward direction means the
 * addresses containing the values grow, where reverse is the opposite. */
void shift_rows(uint8_t state[4][4], bool reverse);

/* Used by the algorithm for the add round key step. Applies a logical xor
 * operaiton to the [state] using the [round]th word of the [schedule]. */
void add_round_key(uint8_t state[4][4], uint32_t schedule[44], uint8_t round);

/* Used by the matrix_mul() function to multiply bytes. It performs the
 * multiplication inside a finite field of GF(2^8), and the reduces the result
 * via a modulo of the irreducible polynomial x^8 + x^4 + x^3 + x + 1,
 * as specified in the AES spec. */
uint8_t multiply(uint8_t data, uint8_t mul);

/* Used by the mix_columns() function. Performs a matrix multiplication using
 * the special multiply() function. The result is stored in [word]. */
void matrix_mul(const uint8_t matrix[4][4], uint8_t word[4]);

/* Used by the algorithm to perform the mix_columns step. */
void mix_columns(uint8_t state[4][4], const uint8_t matrix[4][4]);

/* Massages the password given by the user into a key. This function is not
 * part of the AES specification. */
void create_key(uint8_t key[16], const char *password);

/* Encrypts (if the flag is set) or decrypts (if not)  a volume of data,
 * 128 bits at a time. The encrypted data is stored into the same buffer
 * the original data was provided in. The buffer must be a multiple of 128 bits.
 * Return 0 on success and -1 if the data was not encrypted. */
int edcrypt(bool encrypt, uint8_t *data, uint32_t size, const char *password);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* AES_H */
