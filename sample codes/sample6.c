#include <stdlib.h>
#include <stdio.h>

int main() {
    // Stage 3 Vulnerabilities: Memory Scrubbing & Use-After-Free
    // GCC compiles this perfectly, producing highly insecure software out to production!
    int password = 123;
    
    // The programmer failed to memset/wipe the sensitive variable!
    free(password); 
    
    // The programmer attempts to use a memory pointer that was already freed!
    int leak = password; 
}
