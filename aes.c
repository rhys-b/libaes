/* Author: Rhys Byers
 * Modified: 2022/09/25
 *
 * This library contains functions allowing data to be encrypted according to
 * the AES128 specification. See aes.h for function documentation.
 */
 

#include "aes.h"


void expand_key(uint32_t key[4], uint32_t schedule[44])
{
	uint8_t i;
	uint32_t word;

	memcpy(schedule, key, 16);
	
	for (i = 4; i < 44; i++)
	{
		word = schedule[i - 1];
		if ((i & 0b11) == 0)
		{
			rotate(&word, 1, -1);
			substitute(&word, 4, subbox);
			word = word ^ rcon[(i >> 2) - 1];
		}
		
		schedule[i] = schedule[i - 4] ^ word;
	}
}

void cipher(uint8_t data[16], uint32_t schedule[44])
{
	uint8_t round;
	uint8_t (*state)[4] = data;
	
	add_round_key(state, schedule, 0);
	
	for (round = 1; round < 10; round++)
	{
		substitute(state, 16, subbox);
		shift_rows(state, true);
		mix_columns(state, mix_matrix);
		add_round_key(state, schedule, round);
	}
	
	substitute(state, 16, subbox);
	shift_rows(state, true);
	add_round_key(state, schedule, 10);
}

void decipher(uint8_t data[16], uint32_t schedule[44])
{
	uint8_t round = 9;
	uint8_t (*state)[4] = data;
	
	add_round_key(state, schedule, 10);
	
	for (round = 9; round > 0; round--)
	{
		shift_rows(state, false);
		substitute(state, 16, invsubbox);
		add_round_key(state, schedule, round);
		mix_columns(state, invmix_matrix);
	}

	shift_rows(state, false);
	substitute(state, 16, invsubbox);
	add_round_key(state, schedule, 0);
}

void rotate(uint8_t *word, uint8_t byte_gap, int8_t shift)
{
	uint8_t copy[4];
	uint8_t i;
	
	for (i = 0; i < 4; i++) copy[i] = *(word + byte_gap * i);
	for (i = 0; i < 4; i++) *(((i + shift) & 0b11) * byte_gap + word) = copy[i];
}

void substitute(uint8_t *arr, size_t size, const uint8_t *table)
{
	 for (size_t i = 0; i < size; i++) arr[i] = table[arr[i]];
}

void shift_rows(uint8_t state[4][4], bool reverse)
{
	rotate(&(state[0][1]), 4, 1 - (2 * reverse));
	rotate(&(state[0][2]), 4, 2 - (4 * reverse));
	rotate(&(state[0][3]), 4, 3 - (6 * reverse));
}

void add_round_key(uint8_t state[4][4], uint32_t schedule[44], uint8_t round)
{
	uint8_t i;
	uint32_t *column;
	
	for (i = 0; i < 4; i++)
	{
		column = (uint32_t*)state[i];
		*column = *column ^ schedule[round * 4 + i];
	}
}

uint8_t multiply(uint8_t data, uint8_t mul)
{
	uint16_t work = 0;
	uint16_t mask = 0x8;
	uint16_t mod = 0x8d8;
	int8_t i;
	
	for (i = 3; i >= 0; i--)
	{
		work ^= (data << i) * ((mul & mask) >> i);
		mask = mask >> 1;
	}
	
	for (i = 11; i >= 8; i--)
	{
		work ^= mod * ((mod & work) >> i);
		mod = mod >> 1;
	}
	
	return (uint8_t)work;
}

void matrix_mul(const uint8_t matrix[4][4], uint8_t word[4])
{
	uint8_t i, j;
	uint8_t copy[4];
	
	memcpy(copy, word, 4);
	
	for (i = 0; i < 4; i++)
	{
		word[i] = 0;
		
		for (j = 0; j < 4; j++)
		{
			word[i] ^= multiply(copy[j], matrix[i][j]);
		}
	}
}

void mix_columns(uint8_t state[4][4], const uint8_t matrix[4][4])
{
	for (int i = 0; i < 4; i++)
	{
		matrix_mul(matrix, state[i]);
	}
}

void create_key(uint8_t key[16], const char *password)
{
	memset(key, 0, 16);

	size_t length = strlen(password);

	while (length > 16)
	{
		/* XOR each byte of the password with each byte of the key. */
		for (uint8_t i = 0; i < 16; i++)
		{
			key[i] ^= password[i];
		}

		length -= 16;
		password += 16;
	}

	/* XOR along the length of the remaining bytes. */
	for (uint8_t i = 0; i <= 16 - length; i++)
	{
		for (uint8_t j = 0; j < length; j++)
		{
			key[i + j] ^= password[j];
		}
	}
}

int edcrypt(bool encrypt, uint8_t *data, uint32_t size, const char *password)
{
	if (size % 16 != 0) return -1;

	uint8_t key[16];
	uint32_t schedule[44];

	create_key(key, password);
	expand_key(key, schedule);

	for (uint32_t i = 0; i < size; i += 16)
	{
		if (encrypt) cipher(data, schedule);
		else decipher(data, schedule);

		data += 16;
	}

	return 0;
}
