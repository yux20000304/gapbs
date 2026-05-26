#ifndef GEM5_ROI_H_
#define GEM5_ROI_H_

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace gapbs_gem5_roi {

inline bool IsTruthy(const char *value) {
  if (value == nullptr || value[0] == '\0')
    return false;
  return std::strcmp(value, "0") != 0 && std::strcmp(value, "false") != 0 &&
         std::strcmp(value, "False") != 0 && std::strcmp(value, "FALSE") != 0 &&
         std::strcmp(value, "no") != 0 && std::strcmp(value, "No") != 0 &&
         std::strcmp(value, "NO") != 0;
}

inline bool Enabled() {
  static const bool enabled = IsTruthy(std::getenv("GAPBS_M5_ROI"));
  return enabled;
}

inline void WorkBegin(uint64_t workid, uint64_t threadid) {
  if (!Enabled())
    return;
#if defined(__x86_64__)
  asm volatile(".byte 0x0F, 0x04; .word 0x5a"
               :
               : "D"(workid), "S"(threadid)
               : "memory");
#endif
}

inline void WorkEnd(uint64_t workid, uint64_t threadid) {
  if (!Enabled())
    return;
#if defined(__x86_64__)
  asm volatile(".byte 0x0F, 0x04; .word 0x5b"
               :
               : "D"(workid), "S"(threadid)
               : "memory");
#endif
}

}  // namespace gapbs_gem5_roi

#endif  // GEM5_ROI_H_
