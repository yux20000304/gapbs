// Copyright (c) 2015, The Regents of the University of California (Regents)
// See LICENSE.txt for license details

#ifndef CXL_ALLOCATOR_H_
#define CXL_ALLOCATOR_H_

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <type_traits>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


/*
GAP Benchmark Suite
Class: CXL allocator

Routes selected graph allocations through one shared mmap region. In gem5 SE,
the simulator can special-case GAPBS_CXL_PATH, for example /dev/gem5_cxl_mem,
and back that mapping with shared CXL memory.
*/

namespace gapbs {
namespace cxl {

inline bool IsTruthy(const char *value) {
  if (value == nullptr)
    return false;
  return std::strcmp(value, "1") == 0 ||
         std::strcmp(value, "true") == 0 ||
         std::strcmp(value, "TRUE") == 0 ||
         std::strcmp(value, "yes") == 0 ||
         std::strcmp(value, "YES") == 0 ||
         std::strcmp(value, "on") == 0 ||
         std::strcmp(value, "ON") == 0;
}

inline bool GraphAllocatorRequested() {
  return IsTruthy(std::getenv("GAPBS_CXL_GRAPH"));
}

inline bool StrictMode() {
  return IsTruthy(std::getenv("GAPBS_CXL_STRICT"));
}

inline bool VerboseMode() {
  return IsTruthy(std::getenv("GAPBS_CXL_VERBOSE"));
}

inline size_t ParseSize(const char *value, size_t default_value) {
  if ((value == nullptr) || (*value == '\0'))
    return default_value;

  char *end = nullptr;
  errno = 0;
  unsigned long long parsed = std::strtoull(value, &end, 0);
  if ((errno != 0) || (end == value))
    return default_value;

  unsigned long long multiplier = 1;
  if (*end != '\0') {
    if ((end[1] != '\0') && !(end[1] == 'B' && end[2] == '\0'))
      return default_value;
    switch (*end) {
      case 'k':
      case 'K':
        multiplier = 1024ULL;
        break;
      case 'm':
      case 'M':
        multiplier = 1024ULL * 1024ULL;
        break;
      case 'g':
      case 'G':
        multiplier = 1024ULL * 1024ULL * 1024ULL;
        break;
      case 't':
      case 'T':
        multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
      default:
        return default_value;
    }
  }

  if (parsed > std::numeric_limits<size_t>::max() / multiplier)
    return default_value;
  return static_cast<size_t>(parsed * multiplier);
}

inline size_t AlignUp(size_t value, size_t alignment) {
  size_t mask = alignment - 1;
  return (value + mask) & ~mask;
}

class Allocator {
 public:
  static Allocator& Instance() {
    static Allocator allocator;
    return allocator;
  }

  bool requested() const {
    return requested_;
  }

  bool available() const {
    return base_ != nullptr;
  }

  bool Owns(const void *ptr) const {
    const char *addr = static_cast<const char*>(ptr);
    return (base_ != nullptr) && (addr >= base_) && (addr < base_ + size_);
  }

  void* Allocate(size_t bytes, size_t alignment) {
    if (!requested_ || !available())
      return nullptr;

    if (bytes == 0)
      bytes = 1;
    if (alignment < sizeof(void*))
      alignment = sizeof(void*);

    std::lock_guard<std::mutex> guard(lock_);
    size_t aligned_used = AlignUp(used_, alignment);
    if ((aligned_used > size_) || (bytes > size_ - aligned_used)) {
      std::cerr << "GAPBS CXL allocator out of memory: requested "
                << bytes << " bytes, used " << used_ << " of "
                << size_ << " bytes" << std::endl;
      std::exit(-91);
    }

    void *ptr = base_ + aligned_used;
    used_ = aligned_used + bytes;
    return ptr;
  }

 private:
  Allocator() : requested_(GraphAllocatorRequested()), base_(nullptr),
                size_(0), used_(0), fd_(-1) {
    if (requested_)
      Init();
  }

  ~Allocator() {
    if (base_ != nullptr)
      munmap(base_, size_);
    if (fd_ >= 0)
      close(fd_);
  }

  void Init() {
    const char *path_env = std::getenv("GAPBS_CXL_PATH");
    std::string path = path_env == nullptr ? "/dev/gem5_cxl_mem" : path_env;

    const size_t default_size = 1ULL << 30;
    const char *size_env = std::getenv("GAPBS_CXL_SIZE");
    if (size_env == nullptr)
      size_env = std::getenv("GAPBS_CXL_MAP_SIZE");
    size_ = ParseSize(size_env, default_size);

    fd_ = open(path.c_str(), O_RDWR);
    if ((fd_ < 0) && (path != "/dev/gem5_cxl_mem"))
      fd_ = open(path.c_str(), O_RDWR | O_CREAT, 0600);

    if (fd_ < 0) {
      if (StrictMode()) {
        std::cerr << "Unable to open GAPBS CXL path " << path << ": "
                  << std::strerror(errno) << std::endl;
        std::exit(-90);
      }
      std::cerr << "Warning: unable to open GAPBS CXL path " << path
                << "; graph allocations will use heap fallback" << std::endl;
      size_ = 0;
      return;
    }

    struct stat st;
    if ((fstat(fd_, &st) == 0) && S_ISREG(st.st_mode)) {
      if (ftruncate(fd_, size_) != 0) {
        if (StrictMode()) {
          std::cerr << "Unable to size GAPBS CXL backing file " << path
                    << ": " << std::strerror(errno) << std::endl;
          std::exit(-90);
        }
        std::cerr << "Warning: unable to size GAPBS CXL backing file "
                  << path << "; graph allocations will use heap fallback"
                  << std::endl;
        close(fd_);
        fd_ = -1;
        size_ = 0;
        return;
      }
    }

    void *mapping = mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_, 0);
    if (mapping == MAP_FAILED) {
      if (StrictMode()) {
        std::cerr << "Unable to mmap GAPBS CXL path " << path << ": "
                  << std::strerror(errno) << std::endl;
        std::exit(-90);
      }
      std::cerr << "Warning: unable to mmap GAPBS CXL path " << path
                << "; graph allocations will use heap fallback" << std::endl;
      close(fd_);
      fd_ = -1;
      size_ = 0;
      return;
    }

    base_ = static_cast<char*>(mapping);
    if (VerboseMode()) {
      std::cout << "GAPBS CXL allocator mapped " << size_
                << " bytes from " << path << std::endl;
    }
  }

  bool requested_;
  char *base_;
  size_t size_;
  size_t used_;
  int fd_;
  std::mutex lock_;
};

template <typename T>
T* AllocArray(size_t count) {
  static_assert(std::is_trivially_destructible<T>::value,
                "CXL graph arrays must be trivially destructible");
  size_t alloc_count = count == 0 ? 1 : count;
  if (alloc_count > std::numeric_limits<size_t>::max() / sizeof(T)) {
    std::cerr << "GAPBS CXL allocator size overflow" << std::endl;
    std::exit(-92);
  }

  Allocator &allocator = Allocator::Instance();
  void *storage = allocator.Allocate(alloc_count * sizeof(T), alignof(T));
  if (storage != nullptr) {
    T *typed = static_cast<T*>(storage);
    if (!std::is_trivially_default_constructible<T>::value) {
      for (size_t i = 0; i < alloc_count; i++)
        new (&typed[i]) T();
    }
    return typed;
  }

  return new T[alloc_count];
}

template <typename T>
void FreeArray(T *ptr) {
  if (ptr == nullptr)
    return;
  if (Allocator::Instance().Owns(ptr))
    return;
  delete[] ptr;
}

}  // namespace cxl
}  // namespace gapbs

#endif  // CXL_ALLOCATOR_H_
