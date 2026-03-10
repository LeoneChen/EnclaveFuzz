#include <stddef.h>

extern "C" {
void _set_usp(size_t addr);

size_t _get_usp();
}
