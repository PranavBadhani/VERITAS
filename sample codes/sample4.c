#include <stdio.h>

int main()
{
    // Stage 3 Vulnerability: Format String Error
    // Calling printf with variable variables instead of literals opens the system up to %x and %n arbitrary memory reading/writing!
    int dangerous_input = 0;
    printf(dangerous_input); 
}
