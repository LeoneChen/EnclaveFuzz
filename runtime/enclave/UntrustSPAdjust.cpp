#include "UntrustSPAdjust.hpp"
#include "arch.h"
#include "thread_data.h"
#include <stdint.h>

void set_untrust_sp(size_t addr) {
  thread_data_t *thread_data = get_thread_data();
  ssa_gpr_t *ssa_gpr =
      reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
  ssa_gpr->REG(sp_u) = addr;
}

size_t get_untrust_sp() {
  thread_data_t *thread_data = get_thread_data();
  ssa_gpr_t *ssa_gpr =
      reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
  return ssa_gpr->REG(sp_u);
}