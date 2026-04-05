#pragma once
#include "Malloc.h"
#include "SGXSanRTApp.h"
#include <elf.h>
#include <link.h>
#include <map>

typedef std::map<uptr, uptr> AddrRangeType;
enum ECallCheckType { CHECK_ECALL_PRIVATE, CHECK_ECALL_ALLOWED };

extern bool __thread RunInEnclave;

#if defined(__cplusplus)
extern "C" {
#endif
int dlItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data);
#if defined(__cplusplus)
}
#endif

class EnclaveInfo {
public:
  std::string GetEnclaveFileName() { return mEnclaveFileName; }
  void SetEnclaveFileName(std::string fileName) { mEnclaveFileName = fileName; }

  void SetHandler(struct link_map *handler) { mEnclaveHandler = handler; }
  struct link_map *GetHandler() { return mEnclaveHandler; }

  bool isInEnclaveDSORange(uptr addr, size_t len) {
    for (auto pair : mEnclaveDSOStart2End) {
      // Shouldn't overlap different segments
      if (pair.first <= addr and (addr + len) < pair.second) {
        return true;
      }
    }
    return false;
  }

  void Clear() {
    mEnclaveFileName = "";
    mEnclaveStartAddr = 0;
    mEnclaveDSOStart2End.clear();
    mEnclaveHandler = nullptr;
  }

  void GetEnclaveDSORange(uptr *start, uptr *end) {
    int count = 0;
    for (auto pair : mEnclaveDSOStart2End) {
      if (count == 0) {
        *start = pair.first;
        *end = pair.second;
      } else {
        *start = std::min(*start, pair.first);
        *end = std::max(*end, pair.second);
      }
      count++;
    }
  }

  int DLItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data) {
    auto EnclaveDSOStart = *(uptr *)data;
    if (EnclaveDSOStart == info->dlpi_addr) {
      // Found interesting DSO
      for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD) {
          // Found loadable segment
          uptr beg =
              RoundDownTo(EnclaveDSOStart + phdr->p_vaddr, phdr->p_align);
          uptr end =
              RoundUpTo(EnclaveDSOStart + phdr->p_vaddr + phdr->p_memsz - 1,
                        phdr->p_align);
          mEnclaveDSOStart2End[beg] = end;
          log_debug("%s: [%p, %p]\n", info->dlpi_name, (void *)beg,
                    (void *)end);
        }
      }
      return 1;
    } else {
      return 0;
    }
  }

  void PoisonEnclaveDSOCode();

private:
  std::string mEnclaveFileName = "";
  uptr mEnclaveStartAddr;
  AddrRangeType mEnclaveDSOStart2End;
  struct link_map *mEnclaveHandler;
};
extern EnclaveInfo gEnclaveInfo;
