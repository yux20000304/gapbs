// SPDX-License-Identifier: BSD-3-Clause
//
// CXL shared-memory graph layout for GAPBS.
//
// This header defines a simple self-describing layout stored at the beginning
// of a shared memory region (e.g., ivshmem BAR2). The main goal is to support
// a "ring"/shared-memory build of GAPBS where large graph arrays live in shared
// memory rather than anonymous heap pages.

#ifndef GAPBS_CXL_GRAPH_LAYOUT_H_
#define GAPBS_CXL_GRAPH_LAYOUT_H_

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "cxl_shm.h"

namespace gapbs {
namespace cxl_graph {

static const uint32_t kVersion = 1;
static const uint64_t kMagic = 0x4C58434353425041ULL;  // "APBSCCXL" (LE)

// Flags (bitmask).
static const uint32_t kFlagDirected = 1u << 0;
static const uint32_t kFlagHasInverse = 1u << 1;
static const uint32_t kFlagWeighted = 1u << 2;

// Stored at offset 0 of the mapped region.
struct Header {
  uint64_t magic;
  uint32_t version;
  uint32_t flags;

  uint64_t num_nodes;
  uint64_t num_edges_directed;  // CSR neighbor entries for out-edges.

  uint32_t dest_bytes;          // sizeof(DestID_)
  uint32_t reserved0;

  uint64_t out_offsets_off;     // byte offset from base
  uint64_t out_neigh_off;       // byte offset from base
  uint64_t in_offsets_off;      // 0 if not present
  uint64_t in_neigh_off;        // 0 if not present

  uint64_t total_bytes;         // bytes used in region for this graph
  uint32_t ready;               // 0=not ready, 1=ready
  uint32_t reserved1;
};

inline Header* GetHeader() {
  cxl_shm::Global().InitFromEnv();
  return reinterpret_cast<Header*>(cxl_shm::Global().base());
}

inline void ResetRegion() {
  cxl_shm::Global().InitFromEnv();
  std::memset(cxl_shm::Global().base(), 0, sizeof(Header));
  cxl_shm::Global().Reset(cxl_shm::AlignUp(sizeof(Header), 64));
}

inline void Publish(const Header& h) {
  Header* dst = GetHeader();
  *dst = h;
  // Best-effort: ensure ready becomes visible last.
  __sync_synchronize();
  dst->ready = 1;
  __sync_synchronize();
}

inline bool Ready() {
  Header* h = GetHeader();
  return h->magic == kMagic && h->version == kVersion && h->ready == 1;
}

}  // namespace cxl_graph
}  // namespace gapbs

#endif  // GAPBS_CXL_GRAPH_LAYOUT_H_

