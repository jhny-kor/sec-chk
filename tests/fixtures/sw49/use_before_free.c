#include <stdlib.h>
int read(void) {
  int *p = malloc(sizeof(int));
  int value = *p;
  free(p);
  return value;
}
