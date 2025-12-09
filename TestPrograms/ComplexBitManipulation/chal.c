#include <stdio.h>
#include <string.h>


char enc[] = "\x32\x24\x2c\x34\x33\x20\x28\x3a\x25\x24\x22\x2e\x25\x24\x1e\x32\x34\x22\x22\x24\x32\x32\x60\x3c";

void decode();

int main() {
    printf("Secret admin portal\n");
    printf("+++++++++++++++++++\n\n");
    printf("Enter the KEY: ");

    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);
    size_t len  = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    decode();
    
    printf("\n");

    if (strcmp(enc, buffer) == 0) {
        printf("Welcome, admin.\nYour flag: %s\n", enc);
    } else {
        printf("Invalid KEY. Access violation will be reported.\n");
    }

    
    return 0;
}


void decode() {
   for (int i = 0; i < sizeof(enc) - 1; i++) {
       enc[i] = (~((((enc[i] ^ 0x67) ^ (~enc[i])) ^ 0xDE) ^ (~enc[i] ^ 0xAD)) ^ 0xAA);
    }
}
