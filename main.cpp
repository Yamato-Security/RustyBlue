#include <stdio.h>
#include <stdlib.h>


int main() {
    uint8_t *stack;
    stack = new uint8_t[0xffffffff];
    if (stack != NULL) {
        printf("error new stack.");
    }
}
