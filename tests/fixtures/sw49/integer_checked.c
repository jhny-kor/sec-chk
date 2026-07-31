#include <stdlib.h>
int fixture(char **argv) {
    int index = atoi(argv[1]);
    if (index < 0 || index >= 8) return -1;
    int values[8] = {0};
    return values[index];
}
