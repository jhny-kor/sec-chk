#include <stdlib.h>
int read(void) {
  int *p = malloc(sizeof(int));
  free(p);
  return *p;
}
