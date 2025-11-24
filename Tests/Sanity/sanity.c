#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    printf("Welcome to my scary program!\n");
    printf("Mysterious things happen...\n");
    
    if (argc != 2) {
        printf("Not you.");
        return 1;
    } else if (strlen(argv[1]) < 4) {
        printf("Short.");
        return 1;
    }

    char* magicStr = malloc(4);
    strncpy(magicStr, argv[1], 4); 
    
    if (strcmp(magicStr, "sane") == 0) {
        free(magicStr);
        printf("No mystery.");
        return 0;
    }
    free(magicStr);
    return 1;
}

