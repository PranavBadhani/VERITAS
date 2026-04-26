#include <stdio.h>
#include <string.h>

int main() {
    // Stage 3 Vulnerability: Buffer Overflow
    // GCC might compile this successfully, but Mini_Compiler halts execution.
    int user_input = 0;
    gets(user_input); 
}
