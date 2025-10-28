#include <stdio.h>

int verify(int a, int b) {
    if (a + 3 == b) {
        return 1;
    }
    return 0;
}

int main() {
    int a = 5;
    int b = 2;
    if (verify(a, b)) {
        printf("Good run");
        return 0;
    }
    printf("Failed.");
    return 1;
}
