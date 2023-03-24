#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utilities.h"

void pretty_print(uint8_t* value, int size) {
    for (int i = 0; i < size; i++) {
        printf("0x%x,",value[i]);
    }
    printf("\n");
}


static void shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+1);
    *(state+1)  = *(state+5);
    *(state+5)  = *(state+9);
    *(state+9)  = *(state+13);
    *(state+13) = temp;
    // row2
    temp        = *(state+2);
    *(state+2)  = *(state+10);
    *(state+10) = temp;
    temp        = *(state+6);
    *(state+6)  = *(state+14);
    *(state+14) = temp;
    // row3
    temp        = *(state+15);
    *(state+15) = *(state+11);
    *(state+11) = *(state+7);
    *(state+7)  = *(state+3);
    *(state+3)  = temp;
}


/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+13);
    *(state+13) = *(state+9);
    *(state+9)  = *(state+5);
    *(state+5)  = *(state+1);
    *(state+1)  = temp;
    // row2
    temp        = *(state+14);
    *(state+14) = *(state+6);
    *(state+6)  = temp;
    temp        = *(state+10);
    *(state+10) = *(state+2);
    *(state+2)  = temp;
    // row3
    temp        = *(state+3);
    *(state+3)  = *(state+7);
    *(state+7)  = *(state+11);
    *(state+11) = *(state+15);
    *(state+15) = temp;
}


void mixColumns(uint8_t* plainText)
{
    uint8_t * tempC = malloc(16);

    for (int i = 0; i < 4; ++i)
    {
        tempC[(4*i)+0] = (uint8_t) (mul2[plainText[(4*i)+0]] ^ mul_3[plainText[(4*i)+1]] ^ plainText[(4*i)+2] ^ plainText[(4*i)+3]);
        tempC[(4*i)+1] = (uint8_t) (plainText[(4*i)+0] ^ mul2[plainText[(4*i)+1]] ^ mul_3[plainText[(4*i)+2]] ^ plainText[(4*i)+3]);
        tempC[(4*i)+2] = (uint8_t) (plainText[(4*i)+0] ^ plainText[(4*i)+1] ^ mul2[plainText[(4*i)+2]] ^ mul_3[plainText[(4*i)+3]]);
        tempC[(4*i)+3] = (uint8_t) (mul_3[plainText[(4*i)+0]] ^ plainText[(4*i)+1] ^ plainText[(4*i)+2] ^ mul2[plainText[(4*i)+3]]);
    }

    for (int i = 0; i < 16; ++i)
    {
        plainText[i] = tempC[i];
    }
    free(tempC);
}

/**
 * @brief INVERSE MIX-COLUMNS
 * 
 * @param plainText 
 * @param ciphertext 
 */

/*
         * MixColumns 
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
void inverseMixedColumn (uint8_t* plainText)
{
    uint8_t * tempC = malloc(16);

    for (int i = 0; i < 4; ++i)
    {
        tempC[(4*i)+0] = (uint8_t) (mul_14[plainText[(4*i)+0]] ^ mul_11[plainText[(4*i)+1]] ^ mul_13[plainText[(4*i)+2]] ^ mul_9[plainText[(4*i)+3]]);
        tempC[(4*i)+1] = (uint8_t) (mul_9[plainText[(4*i)+0]] ^ mul_14[plainText[(4*i)+1]] ^ mul_11[plainText[(4*i)+2]] ^ mul_13[plainText[(4*i)+3]]);
        tempC[(4*i)+2] = (uint8_t) (mul_13[plainText[(4*i)+0]] ^ mul_9[plainText[(4*i)+1]] ^ mul_14[plainText[(4*i)+2]] ^ mul_11[plainText[(4*i)+3]]);
        tempC[(4*i)+3] = (uint8_t) (mul_11[plainText[(4*i)+0]] ^ mul_13[plainText[(4*i)+1]] ^ mul_9[plainText[(4*i)+2]] ^ mul_14[plainText[(4*i)+3]]);
    }
    for (int i = 0; i < 16; ++i)
    {
        plainText[i] = tempC[i];
    }
    free(tempC);
}

/**
 * @brief Add (XOR in GF(2^8)) key to plaintext
 * 
 * @param plaintext 
 * @param key 
 */
void add(uint8_t* plaintext, uint8_t* key) {
    uint8_t * tempC = malloc(16);
    for (int i = 0; i < 16; i++) {
        tempC[i] = plaintext[i] ^ key[i];
    }

    for (int i = 0; i < 16; ++i)
    {
        plaintext[i] = tempC[i];
    }
    free(tempC);
}


void sub_bytes(uint8_t* plaintext) {
    uint8_t * tempC = malloc(16);
    for (int i = 0; i < 16; i++) {
        tempC[i] = SBOX[plaintext[i]];
    }

    for (int i = 0; i < 16; ++i)
    {
        plaintext[i] = tempC[i];
    }
    free(tempC);
}

void inverse_sub_bytes(uint8_t* plaintext) {
    uint8_t * tempC = malloc(16);
    for (int i = 0; i < 16; i++) {
        tempC[i] = INV_SBOX[plaintext[i]];
    }

    for (int i = 0; i < 16; ++i)
    {
        plaintext[i] = tempC[i];
    }
    free(tempC);
}


/*! \brief Performs key expansion to generate key schedule
 * from initial set of Key of 4 words.
 * \param round_key  Holds the pointer to store key schedule 
 * \param key        Initial Key received from the user
 */
void KeyExpansion(uint8_t *round_key, uint8_t *key, int rounds) // round_key should be long (round+1)*16
{
	uint8_t i, temp;

	//Retain the initial for round 0
	for ( i = 0; i < 16; i++) {
		round_key[ i ] = key[ i ];
	}

	// Compute Key schedule of block size for each round
	for ( i = 1; i < (rounds + 1); i++) {
		temp = round_key[ i*16 - 4 ];
		round_key[i*16 +  0] = SBOX[ round_key[i*16 - 3] ] ^ round_key[(i-1)*16 + 0] ^ Rcon[ i ];
		round_key[i*16 +  1] = SBOX[ round_key[i*16 - 2] ] ^ round_key[(i-1)*16 + 1];
		round_key[i*16 +  2] = SBOX[ round_key[i*16 - 1] ] ^ round_key[(i-1)*16 + 2];
		round_key[i*16 +  3] = SBOX[ temp ] ^ round_key[ (i-1)*16 + 3 ];

		round_key[i*16 +  4] = round_key[(i-1)*16 + 4] ^ round_key[i*16 + 0];
		round_key[i*16 +  5] = round_key[(i-1)*16 + 5] ^ round_key[i*16 + 1];
		round_key[i*16 +  6] = round_key[(i-1)*16 + 6] ^ round_key[i*16 + 2];
		round_key[i*16 +  7] = round_key[(i-1)*16 + 7] ^ round_key[i*16 + 3];

		round_key[i*16 +  8] = round_key[(i-1)*16 + 8] ^ round_key[i*16 + 4];
		round_key[i*16 +  9] = round_key[(i-1)*16 + 9] ^ round_key[i*16 + 5];
		round_key[i*16 + 10] = round_key[(i-1)*16 +10] ^ round_key[i*16 + 6];
		round_key[i*16 + 11] = round_key[(i-1)*16 +11] ^ round_key[i*16 + 7];

		round_key[i*16 + 12] = round_key[(i-1)*16 +12] ^ round_key[i*16 + 8];
		round_key[i*16 + 13] = round_key[(i-1)*16 +13] ^ round_key[i*16 + 9];
		round_key[i*16 + 14] = round_key[(i-1)*16 +14] ^ round_key[i*16 +10];
		round_key[i*16 + 15] = round_key[(i-1)*16 +15] ^ round_key[i*16 +11];
	}
}