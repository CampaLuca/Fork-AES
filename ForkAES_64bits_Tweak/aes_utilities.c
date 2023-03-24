#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utilities.c"

void forward_round(uint8_t* plaintext);
void inverse_round(uint8_t* plaintext);

void forward_round(uint8_t* plaintext) {
    sub_bytes(plaintext);
    shift_rows(plaintext);
    mixColumns(plaintext);
}

void inverse_round(uint8_t* plaintext) {
    inverseMixedColumn(plaintext);
    inv_shift_rows(plaintext);
    inverse_sub_bytes(plaintext);
}

