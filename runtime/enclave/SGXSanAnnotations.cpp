#include "Poison.hpp"
#include "SGXSanRTConfig.h"
#include <algorithm>

extern "C" {

/// Annotate contiguous container for ASan to detect container overflow.
/// This function maintains the logical bounds of dynamically-sized containers
/// like std::vector in the shadow memory.
///
/// @param beg_p Beginning of the container's allocated memory
/// @param end_p End of the container's capacity (allocated but not used)
/// @param old_mid_p Old end of valid data (before update)
/// @param new_mid_p New end of valid data (after update)
void __sanitizer_annotate_contiguous_container(const void *beg_p,
                                               const void *end_p,
                                               const void *old_mid_p,
                                               const void *new_mid_p) {
  uptr beg = reinterpret_cast<uptr>(beg_p);
  uptr end = reinterpret_cast<uptr>(end_p);
  uptr old_mid = reinterpret_cast<uptr>(old_mid_p);
  uptr new_mid = reinterpret_cast<uptr>(new_mid_p);
  uptr granularity = SHADOW_GRANULARITY;

  // Parameter validation
  sgxsan_error(!(beg <= old_mid && beg <= new_mid && old_mid <= end &&
                 new_mid <= end && IsAligned(beg, granularity)),
               "__sanitizer_annotate_contiguous_container: Invalid parameters\n"
               "beg=%p, end=%p, old_mid=%p, new_mid=%p\n",
               beg_p, end_p, old_mid_p, new_mid_p);

  // Size sanity check: 64-bit max 1TB
  sgxsan_error(end - beg > (1ULL << 40),
               "__sanitizer_annotate_contiguous_container: "
               "Container size too large: %zu bytes\n",
               end - beg);

  log_debug("contiguous_container: beg=%p, end=%p, old_mid=%p -> new_mid=%p\n",
            beg_p, end_p, old_mid_p, new_mid_p);

  // Compute the range of shadow memory that needs to be updated.
  // This is the range that encompasses both old and new boundaries.
  uptr a = RoundDownTo(std::min(old_mid, new_mid), granularity);
  uptr c = RoundUpTo(std::max(old_mid, new_mid), granularity);

  // Compute the new valid region boundaries
  uptr b1 = RoundDownTo(new_mid, granularity);
  uptr b2 = RoundUpTo(new_mid, granularity);

  // Update shadow memory:
  // [a, b1)        - Valid data region: mark as addressable (0x00)
  // [b1, b2)       - Partially valid: mark with byte count
  // [b2, c)        - Invalid/uninitialized region: mark as poisoned (0xfc)
  //
  // This effectively expands or shrinks the "valid" region of the container
  // while poisoning the uninitialized/allocated-but-not-used region.

  PoisonShadow(a, b1 - a, 0);
  PoisonShadow(b2, c - b2, kAsanContiguousContainerOOBMagic);

  // Handle the partial byte at the boundary if new_mid is not aligned
  if (b1 != b2) {
    // Store the number of valid bytes in the last shadow byte
    // This allows detection of accesses to partially-valid bytes
    u8 *shadow_b1 = (u8 *)MEM_TO_SHADOW(b1);
    *shadow_b1 = static_cast<u8>(new_mid - b1);
  }
}

} // extern "C"
