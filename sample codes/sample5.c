#include <stdio.h>

int main() {
    // Stage 3 Vulnerability: Integer Overflow
    // Compiles in GCC just fine, but variables will maliciously loop back to a negative integer boundary at runtime.
    int x = 2000000000;
    int y = 2000000000;
    int z = x + y; 
}
