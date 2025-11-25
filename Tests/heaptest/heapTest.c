#include <stdio.h>
#include <stdlib.h>

typedef struct User {
    int UID;
    char status;
} User;

int main() {
    printf("===Special portal===\n");
    User* temp = malloc(sizeof(User));

    temp->UID = 1;
    temp->status = 'N';

    if (temp->status == 'A') {
        printf("Welcome, admin (UID=%d)\n", temp->UID);
    } else {
        printf("Not admin\nAccess violation (this incident will be reported).\n");
    }
    free(temp);
    return 0;
}
