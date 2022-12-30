#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "aes_utilities.c"

#define HEADER_ROUNDS 5
#define LEFT_ROUNDS 5
#define RIGHT_ROUNDS 5
#define BLOCK_SIZE 16

void encrypt(uint8_t* plaintext, uint8_t* key, uint8_t* tweak);
void decrypt(uint8_t* ciphertext, uint8_t* key, uint8_t* tweak, int side);
void compute_sibling(uint8_t* c0, uint8_t* key, uint8_t* tweak, int side);


void encrypt(uint8_t* plaintext, uint8_t* key, uint8_t* tweak) {
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    uint8_t* round_key;

    for (int i = 0; i < HEADER_ROUNDS; i++) {
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
        }
        add(plaintext, round_key);
        add(plaintext, tweak);

       forward_round(plaintext);
        free(round_key);
    }


    uint8_t* middle_plaintext = malloc(16);
    for (int i = 0; i < 16; i++) {
        middle_plaintext[i] = plaintext[i];
    }

    // ------------------------------------------------------------------ left side
    for (int i = HEADER_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS; i++) {
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
        }

        add(plaintext, round_key);
        add(plaintext, tweak);

       forward_round(plaintext);

        free(round_key);
    }
    // add round key + tweak at the end
    int index = HEADER_ROUNDS+LEFT_ROUNDS;
    round_key = malloc(16);
    for (int j = 0; j < 16; j++) {
        round_key[j] = round_keys[index*BLOCK_SIZE+j];
    }

    add(plaintext, round_key);
    add(plaintext, tweak);
    free(round_key);
    

    printf("Left Side done: ");
    pretty_print(plaintext, BLOCK_SIZE);

    // -------------------------------------------------------------- right side
   
    for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i++) {
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
        }

        add(middle_plaintext, round_key);
        add(middle_plaintext, tweak);

       forward_round(middle_plaintext);

        free(round_key);
    }
    // add round key + tweak at the end
    index = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS;
    round_key = malloc(16);
    for (int j = 0; j < 16; j++) {
        round_key[j] = round_keys[index*BLOCK_SIZE+j];
    }

    add(middle_plaintext, round_key);
    add(middle_plaintext, tweak);
    free(round_key);
    

    printf("Right Side done: ");
    pretty_print(middle_plaintext, BLOCK_SIZE);

}


void decrypt(uint8_t* ciphertext, uint8_t* key, uint8_t* tweak, int side) {      // side = 0 or side = 1
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    uint8_t* round_key;

    if (side == 0) { // LEFT SIDE

        for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i > HEADER_ROUNDS; i--) {
            round_key = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
            }
            add(ciphertext, round_key);
            add(ciphertext, tweak);

            inverse_round(ciphertext);
            free(round_key);
        }

        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[HEADER_ROUNDS*BLOCK_SIZE+j];
        }

        add(ciphertext, round_key);
        add(ciphertext, tweak);
        free(round_key);
    }

    if (side == 1) { // RIGHT SIDE

        for (int i = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i > HEADER_ROUNDS+LEFT_ROUNDS; i--) {
            round_key = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
            }
            add(ciphertext, round_key);
            add(ciphertext, tweak);

            inverse_round(ciphertext);
            free(round_key);
        }

        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[BLOCK_SIZE*(HEADER_ROUNDS+LEFT_ROUNDS)+j];
        }

        add(ciphertext, round_key);
        add(ciphertext, tweak);
        free(round_key);
    }

    // header

    for (int i = HEADER_ROUNDS-1; i >= 0; i--) {
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
        }
        
        inverse_round(ciphertext);
        add(ciphertext, round_key);
        add(ciphertext, tweak);
        free(round_key);
    }


    printf("Decryption DONE: ");
    pretty_print(ciphertext, BLOCK_SIZE);

}


void compute_sibling(uint8_t* c0, uint8_t* key, uint8_t* tweak, int side) {
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    uint8_t* round_key;

    if (side == 0) {    // LEFT
        // decrypt left  encrypt right
        for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i > HEADER_ROUNDS; i--) {
            round_key = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
            }
            add(c0, round_key);
            add(c0, tweak);

            inverse_round(c0);
            free(round_key);
        }
        // add round key + tweak at the end
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[HEADER_ROUNDS*BLOCK_SIZE+j];
        }

        add(c0, round_key);
        add(c0, tweak);
        free(round_key);

        // encrypt right
        for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i++) {
            round_key = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
            }

            add(c0, round_key);
            add(c0, tweak);

           forward_round(c0);

            free(round_key);
        }
        // add round key + tweak at the end
        int index = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS;
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
        }

        add(c0, round_key);
        add(c0, tweak);
        free(round_key);

        printf("From Left to Right: ");
        pretty_print(c0, BLOCK_SIZE);
    }

    if (side == 1) {    // RIGHT
        // decrypt right - encrypt left
        for (int i = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i > HEADER_ROUNDS+LEFT_ROUNDS; i--) {
            round_key = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
            }
            add(c0, round_key);
            add(c0, tweak);

            inverse_round(c0);
            free(round_key);
        }

        // add round key + tweak at the end
        round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[BLOCK_SIZE*(HEADER_ROUNDS+LEFT_ROUNDS)+j];
        }

        add(c0, round_key);
        add(c0, tweak);
        free(round_key);


        for (int i = HEADER_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS; i++) {
            round_key = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
            }

            add(c0, round_key);
            add(c0, tweak);

           forward_round(c0);

            free(round_key);
        }
        // add round key + tweak at the end
        int index = HEADER_ROUNDS+LEFT_ROUNDS;
        uint8_t* round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
        }

        add(c0, round_key);
        add(c0, tweak);
        free(round_key);

        printf("From Right to Left: ");
        pretty_print(c0, BLOCK_SIZE);

    }
}

int main(int argc, char** argv) {
    srand(time(NULL));

    // uint8_t* plaintext = malloc(16);
    // for (int i = 0; i < 16; i++) {
    //     plaintext[i] = (uint8_t)(rand() % 256);
    // }

    // uint8_t* key = malloc(16);
    // for (int i = 0; i < 16; i++) {
    //     key[i] = (uint8_t)(rand() % 256);
    // }

    // uint8_t* tweak = malloc(16);
    // for (int i = 0; i < 16; i++) {
    //     tweak[i] = (uint8_t)(rand() % 256);
    // }

    // pretty_print(plaintext, BLOCK_SIZE);
    // pretty_print(key, BLOCK_SIZE);
    // pretty_print(tweak, BLOCK_SIZE);

    // encrypt(plaintext, key, tweak);

    uint8_t plaintext[16] = {0x6e,0xbb,0x8e,0x9e,0x3f,0xcb,0xff,0x21,0x88,0xe0,0xeb,0xca,0x82,0xf4,0x2f,0x6};
    uint8_t key[16] = {0x52,0x92,0x5d,0x98,0x6e,0xf1,0xd,0x26,0xf2,0xad,0x28,0xb2,0x58,0xd6,0x7c,0xc6};
    uint8_t tweak[16] = {0x91,0xa,0x64,0xd0,0xd6,0x63,0xf1,0x5e,0x44,0xdd,0x28,0xc6,0xd1,0x58,0xcc,0x24};

    uint8_t left[16] = {0xb9,0x7f,0x17,0x4a,0xd2,0xde,0x53,0xb4,0x9,0x77,0xc1,0xe9,0xc8,0x4c,0x68,0x83};
    uint8_t right[16] = {0x42,0xde,0x6e,0xfb,0xc8,0x8b,0x74,0xe9,0x78,0xae,0x27,0xbf,0xfb,0x4,0x40,0x2a};

    compute_sibling(left, key, tweak, 0);

    return 0;
}