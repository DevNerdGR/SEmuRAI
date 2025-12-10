#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct User {
    int UID;
    char* name;
};

int gen(struct User u) {
    int c = 10;
    for (int sum = 0; sum < strlen(u.name); sum++) {
       c = (sum + ((u.name[sum] ^ 0x67) + (u.UID ^ c))) ^ (sum + u.UID);
    }
    return c ^ 0xDEAD;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: keygen1 [UID] [NAME]\n");
        return 1;
    }

    struct User u;
    u.UID = atoi(argv[1]);
    u.name = argv[2];

    printf("Keygen for user %s (UID=%d)\n", u.name, u.UID);

    int key = gen(u);

    if (key == 57156 && strcmp(u.name, "Warrior") == 0) {
        printf("Good hunting. %d\n", key);
    } else {
	printf("Failed.\n");
    }

    return 0;
}


