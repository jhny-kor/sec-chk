#include <string.h>
void copy(const char *input) { char dst[8]; strncpy(dst, input, sizeof(dst) - 1); }
