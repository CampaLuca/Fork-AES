#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utilities.h"

void pretty_print(uint8_t* value, int size) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("0x%x,",value[j*4+i]);
        }
        printf("\n");
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




// d6 8f c1 f1 d4 64 2d 3 f6 7 51 fa 2b 3a 47 40 
// 3f fe 78 e5 eb 9a 55 e6 1d 9d 4 1c 36 a7 43 5c 
// 30 4c b5 d4 db d6 e0 32 c6 4b e4 2e f0 ec a7 72 
// a4 4a 9e af 7f 9c 7e 9d b9 d7 9a b3 49 3b 3d c1 
// 44 ed 5b 1d 3b 71 25 80 82 a6 bf 33 cb 9d 82 f2 
// a2 26 68 38 99 57 4d b8 1b f1 f2 8b d0 6c 70 79 
// af db 76 f8 36 8c 3b 40 2d 7d c9 cb fd 11 b9 b2 
// b5 f0 cd 30 83 7c f6 70 ae 1  3f bb 53 10 86 9 ------------
// 3e 47 a3 f8 bd 3b 55 88 13 3a 6a 33 40 2a ec 3a 
// eb 5  44 f  56 3e 11 87 45 4  7b b4 5  2e 97 8e ------------

// aa 17 e5 36 77 d5 e1 e6 c1 b8 d1 96 eb b6 a a6 
// 3 f2 ca 53 74 27 2b b5 b5 9f fa 23 5e 29 f0 85 
// bf a2 5e 45 cb 85 75 f0 7e 1a 8f d3 20 33 7f 56 
// 16 b9 19 e3 dd 3c 6c 13 a3 26 e3 c0 83 15 9c 96 
// 55 e7 4b 10 88 db 27 3 2b fd c4 c3 a8 e8 58 55 
// 68 18 a7 91 e0 c3 80 92 cb 3e 44 51 63 d6 1c 4 
// 4c e3 a5 52 ac 20 25 c0 67 1e 61 91 4 c8 7d 95 
// be a5 a8 74 12 85 8d b4 75 9b ec 25 71 53 91 b0 
// 92 15 cb 71 77 9d 67 43 e7 8e 27 54 6 ce f6 f3 


// sbox(d1) --> 0x18
// sbox(91) --> 0xa8
// sbox(7d) --> 0x46
// sbox(1c) --> 0xfb
// sbox(58) --> 0xff
// sbox(9c) --> 0x5e
// sbox(7f) --> 0x1b
// sbox(f0) --> 0x50
// sbox(a)  --> 0xe5

// sbox(ec) -> 0x42
// sbox(86) -> 0xb7
// sbox(b9) -> 0x2b
// sbox(70) -> 0xfd
// sbox(82) -> 0xcb
// sbox(3d) -> 0xa7
// sbox(a7) -> 0x6
// sbox(43) -> 0xb2
// sbox(47) -> 0x71

void KeyExpansion_from_intermediate_key(uint8_t* round_key, uint8_t* start_key, int start_key_number, int max_rounds) {
    uint8_t i, temp;

	//Retain the initial for round 7
	for ( i = 0; i < 16; i++) {
		round_key[16*start_key_number+ i ] = start_key[ i ];
	}

    // Compute Key schedule of block size for each round less than start_key_number (the round for which we know the intermediate key)
	for ( i = start_key_number; i >= 1; i--) {
        round_key[(i-1)*16 +12] = round_key[i*16 + 12] ^ round_key[i*16 + 8];
		round_key[(i-1)*16 +13] = round_key[i*16 + 13] ^ round_key[i*16 + 9];
		round_key[(i-1)*16 +14] = round_key[i*16 + 14] ^ round_key[i*16 +10];
		round_key[(i-1)*16 +15] = round_key[i*16 + 15] ^ round_key[i*16 +11];

        round_key[(i-1)*16 + 8] = round_key[i*16 +  8] ^ round_key[i*16 + 4];
		round_key[(i-1)*16 + 9] = round_key[i*16 +  9] ^ round_key[i*16 + 5];
		round_key[(i-1)*16 +10] = round_key[i*16 + 10] ^ round_key[i*16 + 6];
		round_key[(i-1)*16 +11] = round_key[i*16 + 11] ^ round_key[i*16 + 7];

        round_key[(i-1)*16 + 4] = round_key[i*16 +  4] ^ round_key[i*16 + 0];
		round_key[(i-1)*16 + 5] = round_key[i*16 +  5] ^ round_key[i*16 + 1];
		round_key[(i-1)*16 + 6] = round_key[i*16 +  6] ^ round_key[i*16 + 2];
		round_key[(i-1)*16 + 7] = round_key[i*16 +  7] ^ round_key[i*16 + 3];

		temp = round_key[ i*16 - 4 ];
		round_key[(i-1)*16 + 0] = SBOX[ round_key[i*16 - 3] ] ^ round_key[i*16 +  0] ^ Rcon[ i ];
		round_key[(i-1)*16 + 1] = SBOX[ round_key[i*16 - 2] ] ^ round_key[i*16 +  1];
		round_key[(i-1)*16 + 2] = SBOX[ round_key[i*16 - 1] ] ^ round_key[i*16 +  2];
		round_key[ (i-1)*16 + 3 ] = SBOX[ temp ] ^ round_key[i*16 +  3];	
	}

    // Compute Key schedule of block size for each round greater than start_key_number (the round for which we know the intermediate key)
    for ( i = start_key_number+1; i < (max_rounds + 1); i++) {
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


void KeyExpansionModified(uint8_t *round_key, uint8_t *key, int rounds) // round_key should be long (round+1)*16
{
	uint8_t i, temp;

	//Retain the initial for round 0
	for ( i = 0; i < 16; i++) {
		round_key[ i ] = key[ i ];
	}

	// Compute Key schedule of block size for each round
	for ( i = 1; i < (rounds + 1); i++) {
		temp = round_key[ i*16 - 4 ];
		
        round_key[i*16 +  0] = SBOX[ round_key[i*16 - 3] ] ^ round_key[(i-1)*16 + 0] ^ 0xb2;
		//round_key[i*16 +  1] = SBOX[ round_key[i*16 - 2] ] ^ round_key[(i-1)*16 + 1];
		
		round_key[i*16 +  4] = round_key[(i-1)*16 + 4] ^ round_key[i*16 + 0];
		round_key[i*16 +  5] = round_key[(i-1)*16 + 5] ^ round_key[i*16 + 1]; 

		round_key[i*16 +  8] = round_key[(i-1)*16 + 8] ^ round_key[i*16 + 4];
		round_key[i*16 +  9] = round_key[(i-1)*16 + 9] ^ round_key[i*16 + 5];
		
		round_key[i*16 + 12] = round_key[(i-1)*16 +12] ^ round_key[i*16 + 8];
		round_key[i*16 + 13] = round_key[(i-1)*16 +13] ^ round_key[i*16 + 9];
		
	}
}