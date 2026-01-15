// SPDX-License-Identifier: BSD-3-Clause
//
// GAPBS CXL shared-memory helper.
//
// This file is NOT part of upstream GAPBS. It is used by cxl-sec-dsm-sim to
// allocate graph storage from a shared memory region (e.g., ivshmem BAR2 via
// `/sys/bus/pci/devices/.../resource2` or a regular file like `/dev/shm/...`).
//
// The code is intentionally minimal and C++11-friendly (no exceptions).

#ifndef GAPBS_CXL_SHM_H_
#define GAPBS_CXL_SHM_H_

#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <string>

namespace gapbs {
namespace cxl_shm {

inline std::string GetEnvStr(const char* key) {
  const char* v = std::getenv(key);
  return (v && *v) ? std::string(v) : std::string();
}

inline bool ParseSizeBytes(const std::string& s, size_t* out_bytes) {
  if (!out_bytes)
    return false;
  if (s.empty())
    return false;

  const char* str = s.c_str();
  char* end = nullptr;
  errno = 0;
  unsigned long long v = std::strtoull(str, &end, 0);
  if (errno != 0 || end == str)
    return false;

  unsigned long long mul = 1;
  if (end && *end) {
    // Accept a single suffix: K/M/G (base 1024).
    if (end[1] != '\0')
      return false;
    char suf = *end;
    if (suf >= 'A' && suf <= 'Z')
      suf = static_cast<char>(suf - 'A' + 'a');
    if (suf == 'k')
      mul = 1024ULL;
    else if (suf == 'm')
      mul = 1024ULL * 1024ULL;
    else if (suf == 'g')
      mul = 1024ULL * 1024ULL * 1024ULL;
    else
      return false;
  }

  unsigned long long bytes = v * mul;
  if (mul != 0 && bytes / mul != v)
    return false;
  *out_bytes = static_cast<size_t>(bytes);
  return true;
}

inline size_t AlignUp(size_t n, size_t a) {
  return (n + (a - 1)) & ~(a - 1);
}

class Mapping {
 public:
  Mapping() : fd_(-1), base_(nullptr), size_(0), next_off_(0) {}

  ~Mapping() {
    if (base_ != nullptr && size_ != 0) {
      munmap(base_, size_);
    }
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  Mapping(const Mapping&) = delete;
  Mapping& operator=(const Mapping&) = delete;

  void InitFromEnv() {
    if (Initialized())
      return;

    // Prefer GAPBS-specific env vars, but fall back to existing cxl-sec-dsm-sim
    // knobs for convenience.
    std::string path = GetEnvStr("GAPBS_CXL_PATH");
    if (path.empty())
      path = GetEnvStr("CXL_SHM_PATH");
    if (path.empty())
      path = GetEnvStr("CXL_RING_PATH");
    if (path.empty())
      path = "/dev/shm/gapbs_cxl_shared.raw";

    std::string size_str = GetEnvStr("GAPBS_CXL_MAP_SIZE");
    if (size_str.empty())
      size_str = GetEnvStr("CXL_SHM_MAP_SIZE");
    if (size_str.empty())
      size_str = GetEnvStr("CXL_RING_MAP_SIZE");
    if (size_str.empty())
      size_str = "134217728";  // 128 MiB

    size_t map_size = 0;
    if (!ParseSizeBytes(size_str, &map_size) || map_size == 0) {
      std::cerr << "[gapbs] Invalid GAPBS_CXL_MAP_SIZE: '" << size_str << "'"
                << std::endl;
      std::exit(-101);
    }

    Init(path, map_size);
  }

  void Init(const std::string& path, size_t map_size) {
    if (Initialized()) {
      std::cerr << "[gapbs] CXL shm mapping already initialized" << std::endl;
      std::exit(-102);
    }
    if (map_size == 0) {
      std::cerr << "[gapbs] CXL shm map size must be > 0" << std::endl;
      std::exit(-103);
    }

    // Try open without O_CREAT first (device-like files in /sys won't support
    // creation). If missing, fall back to creating a regular file.
    int fd = open(path.c_str(), O_RDWR, 0);
    if (fd < 0 && errno == ENOENT) {
      fd = open(path.c_str(), O_RDWR | O_CREAT, 0666);
    }
    if (fd < 0) {
      std::cerr << "[gapbs] Failed to open GAPBS_CXL_PATH='" << path << "': "
                << std::strerror(errno) << std::endl;
      std::exit(-104);
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
      std::cerr << "[gapbs] fstat(" << path << ") failed: "
                << std::strerror(errno) << std::endl;
      close(fd);
      std::exit(-105);
    }

    // Ensure regular files are large enough.
    if (S_ISREG(st.st_mode)) {
      if (static_cast<size_t>(st.st_size) < map_size) {
        if (ftruncate(fd, static_cast<off_t>(map_size)) != 0) {
          std::cerr << "[gapbs] ftruncate(" << path << ", " << map_size
                    << ") failed: " << std::strerror(errno) << std::endl;
          close(fd);
          std::exit(-106);
        }
      }
    }

    void* base = mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                      0);
    if (base == MAP_FAILED) {
      std::cerr << "[gapbs] mmap(" << path << ", " << map_size << ") failed: "
                << std::strerror(errno) << std::endl;
      close(fd);
      std::exit(-107);
    }

    fd_ = fd;
    base_ = base;
    size_ = map_size;
    next_off_ = 0;
    path_ = path;

    std::cerr << "[gapbs] CXL shm mapped: path=" << path_ << " size=" << size_
              << " base=" << base_ << std::endl;
  }

  bool Initialized() const { return base_ != nullptr && size_ != 0; }

  void Reset(size_t start_offset) {
    if (!Initialized()) {
      std::cerr << "[gapbs] CXL shm mapping not initialized" << std::endl;
      std::exit(-108);
    }
    next_off_ = start_offset;
  }

  void* AllocBytes(size_t bytes, size_t align) {
    if (!Initialized()) {
      std::cerr << "[gapbs] CXL shm mapping not initialized" << std::endl;
      std::exit(-109);
    }
    if (align == 0 || (align & (align - 1)) != 0) {
      std::cerr << "[gapbs] AllocBytes: invalid align=" << align << std::endl;
      std::exit(-110);
    }
    size_t off = AlignUp(next_off_, align);
    if (off > size_ || bytes > size_ - off) {
      std::cerr << "[gapbs] CXL shm out of space: need " << bytes
                << " bytes (align " << align << "), used " << next_off_
                << " / " << size_ << std::endl;
      std::exit(-111);
    }
    void* p = static_cast<uint8_t*>(base_) + off;
    next_off_ = off + bytes;
    return p;
  }

  template <typename T>
  T* AllocArray(size_t count, size_t align = alignof(T)) {
    size_t bytes = count * sizeof(T);
    void* p = AllocBytes(bytes, align);
    return reinterpret_cast<T*>(p);
  }

  bool Contains(const void* p) const {
    if (!Initialized() || !p)
      return false;
    const uintptr_t b = reinterpret_cast<uintptr_t>(base_);
    const uintptr_t x = reinterpret_cast<uintptr_t>(p);
    return x >= b && x < (b + size_);
  }

  void* base() const { return base_; }
  size_t size() const { return size_; }
  size_t used() const { return next_off_; }
  const std::string& path() const { return path_; }

 private:
  int fd_;
  void* base_;
  size_t size_;
  size_t next_off_;
  std::string path_;
};

inline Mapping& Global() {
  static Mapping m;
  return m;
}

inline bool PtrInCxlShm(const void* p) {
  return Global().Contains(p);
}

}  // namespace cxl_shm
}  // namespace gapbs

#endif  // GAPBS_CXL_SHM_H_
