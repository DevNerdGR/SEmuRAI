#include <stdio.h>
#include <string.h>
#include <time.h>
#include "obf_ops.h"

char ENC[23] = {0x16, 0x0, 0x8, 0x10, 0x17, 0x4, 0xc, 0x1e, 0x51, 0x3a, 0x6, 0x9, 0x0, 0x51, 0x17, 0x0, 0x1, 0x3a, 0x12, 0xa, 0x12, 0x18, 0x00};

int check() {
    return 1 == 2;
}

int verify(char creds[10]) {
    int sum = 0;
    for (int i = 2; i < 10; i++) {
        sum = sum + creds[i];
    }
    // First 2 bytes should be 0xde and 0xbb, name should be "samurai!"
    
    return (((unsigned char) creds[0] + (unsigned char) creds[1]  == 409) && (sum == 787));
}

void getFlag(char code[10]) {
    for (int i = 0; i < 22; i++) {
        ENC[i] = ENC[i] ^ XOR_2((unsigned char) code[0],  (unsigned char) code[1]);
    }
}

int main() {
    printf("Admin portal.\n");
    printf("Reading credentials...\n");
    
    char code[10];

    if (check()) {
        printf("Credentials read.\n");
    } else {
        printf("Credentials read fail.\n");
        printf("Using default values...\n");
        time_t curr = time(NULL);
        code[0] = (char) (curr & 0xFF);
        code[1] = (char) ((curr >> 8) & 0xFF);
        code[2] = 'w';
        code[3] = 'a';
        code[4] = 'r';
        code[5] = 'r';
        code[6] = 'i';
        code[7] = 'o';
        code[8] = 'r';
        code[9] = '!';
        printf("[DEBUG] %x %x\n", (unsigned char) code[0], (unsigned char) code[1]);
    }


    if (verify(code)) {
        getFlag(code);
        printf("Correct! Flag is: %s\n", ENC);
    } else {
        printf("Failed.\n");
    }
    return 0;
}

