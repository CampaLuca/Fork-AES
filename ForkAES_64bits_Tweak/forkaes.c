#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "aes_utilities.c"
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "forkaes_configuration.h"

void encrypt(uint8_t* plaintext, uint8_t* key, uint8_t* t, uint8_t* left, uint8_t* right);
void decrypt(uint8_t* ciphertext, uint8_t* key, uint8_t* t, int side);
void compute_sibling(uint8_t* c0, uint8_t* key, uint8_t* t, int side);


void encrypt(uint8_t* plaintext, uint8_t* key, uint8_t* t, uint8_t* left, uint8_t* right) {
    uint8_t* tweak = (uint8_t*) calloc(16,sizeof(uint8_t));
    tweak[0] = t[0];
    tweak[1] = t[1];
    tweak[4] = t[2];
    tweak[5] = t[3];
    tweak[8] = t[4];
    tweak[9] = t[5];
    tweak[12] = t[6];
    tweak[13] = t[7];

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
    

    // printf("Left Side done: ");
    // pretty_print(plaintext, BLOCK_SIZE);
    // saving left side into right array
    for (int i = 0; i < 16; i++) {
        left[i] = plaintext[i];
    }

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
    

    // printf("Right Side done: ");
    // pretty_print(middle_plaintext, BLOCK_SIZE);

    // saving right side into right array
    for (int i = 0; i < 16; i++) {
        right[i] = middle_plaintext[i];
    }

}


void decrypt(uint8_t* ciphertext, uint8_t* key, uint8_t* t, int side) {      // side = 0 or side = 1
    uint8_t* tweak = (uint8_t*) calloc(16,sizeof(uint8_t));
    tweak[0] = t[0];
    tweak[1] = t[1];
    tweak[4] = t[2];
    tweak[5] = t[3];
    tweak[8] = t[4];
    tweak[9] = t[5];
    tweak[12] = t[6];
    tweak[13] = t[7];

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


    // printf("Decryption DONE: ");
    // pretty_print(ciphertext, BLOCK_SIZE);

}


void compute_sibling(uint8_t* c0, uint8_t* key, uint8_t* t, int side) {
    uint8_t* tweak = (uint8_t*) calloc(16,sizeof(uint8_t));
    tweak[0] = t[0];
    tweak[1] = t[1];
    tweak[4] = t[2];
    tweak[5] = t[3];
    tweak[8] = t[4];
    tweak[9] = t[5];
    tweak[12] = t[6];
    tweak[13] = t[7];


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

        //printf("From Left to Right: ");
        //pretty_print(c0, BLOCK_SIZE);
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

           //forward_round(c0);
           sub_bytes(c0);

        //    printf("IL testo è dopo subbytes: ");
        //    pretty_print(c0, 16);

           shift_rows(c0);
           mixColumns(c0);

            free(round_key);
        }
        // add round key + tweak at the end
        int index = HEADER_ROUNDS+LEFT_ROUNDS;
        uint8_t* round_key = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
        }

        // printf("K6 equals to: ");
        // pretty_print(round_key, 16);

        add(c0, round_key);
        add(c0, tweak);
        free(round_key);

        //printf("From Right to Left: ");
        //pretty_print(c0, BLOCK_SIZE);

    }
}

int main(int argc, char** argv) {
    srand(time(NULL));

    uint8_t* plaintext = malloc(16);
    for (int i = 0; i < 16; i++) {
        plaintext[i] = (uint8_t)(rand() % 256);
    }

    uint8_t* key = malloc(16);
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }

    uint8_t* tweak = malloc(8);
    for (int i = 0; i < 8; i++) {
        tweak[i] = (uint8_t)(rand() % 256);
    }

    uint8_t* c0 = malloc(16);
    uint8_t* c1 = malloc(16);

    pretty_print(plaintext, BLOCK_SIZE);
    pretty_print(key, BLOCK_SIZE);
    pretty_print(tweak, BLOCK_SIZE);

    encrypt(plaintext, key, tweak, c0, c1);

    pretty_print(c0, BLOCK_SIZE);
    pretty_print(c1, BLOCK_SIZE);

    return 0;
}