#include "arch.h"
#include "thread_data.h"
#include <stddef.h>
#include <stdint.h>

extern "C" {
void _set_usp(size_t addr) {
  (reinterpret_cast<ssa_gpr_t *>(get_thread_data()->first_ssa_gpr))->REG(sp_u) =
      addr;
}

size_t _get_usp() {
  return (reinterpret_cast<ssa_gpr_t *>(get_thread_data()->first_ssa_gpr))
      ->REG(sp_u);
}
}
