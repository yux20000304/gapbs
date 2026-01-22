// Copyright (c) 2015, The Regents of the University of California (Regents)
// See LICENSE.txt for license details

#ifndef BUILDER_H_
#define BUILDER_H_

#include <algorithm>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <type_traits>
#include <utility>

#include "command_line.h"
#include "generator.h"
#include "graph.h"
#include "platform_atomics.h"
#include "pvector.h"
#include "reader.h"
#include "timer.h"
#include "util.h"

#ifdef GAPBS_CXL_SHM
#include <unistd.h>

#include "cxl_graph_layout.h"
#include "cxl_sec.h"
#endif


/*
GAP Benchmark Suite
Class:  BuilderBase
Author: Scott Beamer

Given arguments from the command line (cli), returns a built graph
 - MakeGraph() will parse cli and obtain edgelist to call
   MakeGraphFromEL(edgelist) to perform the actual graph construction
 - edgelist can be from file (Reader) or synthetically generated (Generator)
 - Common case: BuilderBase typedef'd (w/ params) to be Builder (benchmark.h)
*/


template <typename NodeID_, typename DestID_ = NodeID_,
          typename WeightT_ = NodeID_, bool invert = true>
class BuilderBase {
  typedef EdgePair<NodeID_, DestID_> Edge;
  typedef pvector<Edge> EdgeList;

  const CLBase &cli_;
  bool symmetrize_;
  bool needs_weights_;
  bool in_place_ = false;
  int64_t num_nodes_ = -1;

 public:
  explicit BuilderBase(const CLBase &cli) : cli_(cli) {
    symmetrize_ = cli_.symmetrize();
    needs_weights_ = !std::is_same<NodeID_, DestID_>::value;
    in_place_ = cli_.in_place();
    if (in_place_ && needs_weights_) {
      std::cout << "In-place building (-m) does not support weighted graphs"
                << std::endl;
      exit(-30);
    }
  }

#ifdef GAPBS_CXL_SHM
  enum class CxlMode {
    kPublish,
    kAttach,
    kAuto,
  };

  static bool EnvEnabledLocal(const char* key) {
    const char* v = std::getenv(key);
    return v && *v && *v != '0';
  }

  static unsigned EnvU32Local(const char* key, unsigned def) {
    const char* v = std::getenv(key);
    if (!v || !*v) return def;
    return static_cast<unsigned>(std::strtoul(v, nullptr, 0));
  }

  static CxlMode GetCxlMode() {
    const char* v = std::getenv("GAPBS_CXL_MODE");
    if (!v || !*v) return CxlMode::kPublish;
    if (std::strcmp(v, "publish") == 0) return CxlMode::kPublish;
    if (std::strcmp(v, "attach") == 0) return CxlMode::kAttach;
    if (std::strcmp(v, "auto") == 0) return CxlMode::kAuto;
    std::cerr << "[gapbs] Unknown GAPBS_CXL_MODE='" << v
              << "', expected publish|attach|auto (defaulting to publish)" << std::endl;
    return CxlMode::kPublish;
  }

  static bool WaitGraphReady(unsigned timeout_ms) {
    unsigned waited = 0;
    while (waited < timeout_ms) {
      if (gapbs::cxl_graph::Ready()) return true;
      usleep(10 * 1000);
      waited += 10;
    }
    return false;
  }

  CSRGraph<NodeID_, DestID_, invert> LoadFromCxlShm() {
    using gapbs::cxl_graph::Header;
    using gapbs::cxl_graph::kFlagDirected;
    using gapbs::cxl_graph::kFlagEncrypted;
    using gapbs::cxl_graph::kFlagHasPublic;
    using gapbs::cxl_graph::kFlagHasInverse;
    using gapbs::cxl_graph::kVersion;

    const uint64_t attach_t0 = gapbs::cxl_shm::NowNs();
    uint64_t wait_ms = 0;
    uint64_t decrypt_ms = 0;
    uint64_t pretouch_ms = 0;

    const bool pretouch = EnvEnabledLocal("GAPBS_CXL_PRETOUCH");
    auto do_pretouch = [&](const void* ptr, size_t len) {
      if (!pretouch || !ptr || len == 0) return;
      long page = sysconf(_SC_PAGESIZE);
      const size_t step = (page > 0) ? static_cast<size_t>(page) : 4096;
      const volatile unsigned char* p = reinterpret_cast<const volatile unsigned char*>(ptr);
      volatile unsigned char sink = 0;
      for (size_t off = 0; off < len; off += step) {
        sink ^= p[off];
      }
      sink ^= p[len - 1];
      (void)sink;
    };

    auto log_attach = [&]() {
      const uint64_t total_ms = (gapbs::cxl_shm::NowNs() - attach_t0) / 1000000ULL;
      std::cerr << "[gapbs] CXL attach: total_ms=" << total_ms
                << " wait_ms=" << wait_ms
                << " decrypt_ms=" << decrypt_ms
                << " pretouch_ms=" << pretouch_ms
                << std::endl;
    };

    gapbs::cxl_shm::Mapping& shm = gapbs::cxl_shm::Global();
    shm.InitFromEnv();

    unsigned timeout_ms = EnvU32Local("GAPBS_CXL_ATTACH_TIMEOUT_MS", 30000);
    const uint64_t wait_t0 = gapbs::cxl_shm::NowNs();
    if (!WaitGraphReady(timeout_ms)) {
      std::cerr << "[gapbs] CXL graph not ready after " << timeout_ms << " ms"
                << std::endl;
      std::exit(-131);
    }
    wait_ms = (gapbs::cxl_shm::NowNs() - wait_t0) / 1000000ULL;

    const Header* hdr = gapbs::cxl_graph::GetHeader();
    Header h = *hdr;
    __sync_synchronize();
    if (h.version != kVersion) {
      std::cerr << "[gapbs] Unsupported CXL graph header version: " << h.version << std::endl;
      std::exit(-132);
    }
    if (h.dest_bytes != sizeof(DestID_)) {
      std::cerr << "[gapbs] CXL graph type mismatch: header.dest_bytes=" << h.dest_bytes
                << " but sizeof(DestID_)=" << sizeof(DestID_) << std::endl;
      std::exit(-133);
    }

    const bool directed = (h.flags & kFlagDirected) != 0;
    const bool has_inverse = (h.flags & kFlagHasInverse) != 0;
    const bool encrypted = (h.flags & kFlagEncrypted) != 0;
    const int64_t n = static_cast<int64_t>(h.num_nodes);
    if (n < 0) {
      std::cerr << "[gapbs] Invalid CXL graph header num_nodes=" << h.num_nodes << std::endl;
      std::exit(-134);
    }

    const size_t nn = static_cast<size_t>(n);
    const size_t out_offsets_bytes = (nn + 1) * sizeof(SGOffset);
    const size_t out_entries = static_cast<size_t>(h.num_edges_directed);
    const size_t out_neigh_bytes = out_entries * static_cast<size_t>(h.dest_bytes);

    const unsigned char* mm = reinterpret_cast<const unsigned char*>(shm.base());

    if (!encrypted) {
      pvector<SGOffset> out_offsets(nn + 1);
      std::memcpy(out_offsets.data(), mm + h.out_offsets_off, out_offsets_bytes);
      DestID_* out_neigh = reinterpret_cast<DestID_*>(const_cast<unsigned char*>(mm + h.out_neigh_off));
      DestID_** out_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(out_offsets, out_neigh);

      if (!directed) {
        const uint64_t pt0 = gapbs::cxl_shm::NowNs();
        do_pretouch(out_neigh, out_neigh_bytes);
        pretouch_ms = (gapbs::cxl_shm::NowNs() - pt0) / 1000000ULL;
        log_attach();
        return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh);
      }
      if (has_inverse) {
        const size_t in_offsets_bytes = (nn + 1) * sizeof(SGOffset);
        pvector<SGOffset> in_offsets(nn + 1);
        std::memcpy(in_offsets.data(), mm + h.in_offsets_off, in_offsets_bytes);
        DestID_* in_neigh =
            reinterpret_cast<DestID_*>(const_cast<unsigned char*>(mm + h.in_neigh_off));
        DestID_** in_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(in_offsets, in_neigh);
        const size_t in_entries = static_cast<size_t>(in_offsets[n]);
        const size_t in_neigh_bytes = in_entries * static_cast<size_t>(h.dest_bytes);
        const uint64_t pt0 = gapbs::cxl_shm::NowNs();
        do_pretouch(out_neigh, out_neigh_bytes);
        do_pretouch(in_neigh, in_neigh_bytes);
        pretouch_ms = (gapbs::cxl_shm::NowNs() - pt0) / 1000000ULL;
        log_attach();
        return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh, in_index, in_neigh);
      }
      const uint64_t pt0 = gapbs::cxl_shm::NowNs();
      do_pretouch(out_neigh, out_neigh_bytes);
      pretouch_ms = (gapbs::cxl_shm::NowNs() - pt0) / 1000000ULL;
      log_attach();
      return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh, nullptr, nullptr);
    }

#ifndef GAPBS_CXL_SECURE
    (void)out_neigh_bytes;
    std::cerr << "[gapbs] CXL graph is encrypted, but this binary was built without GAPBS_CXL_SECURE"
              << std::endl;
    std::exit(-135);
#else
    const uint64_t dec_t0 = gapbs::cxl_shm::NowNs();
    if (!gapbs::cxl_sec::EnvEnabled("CXL_SEC_ENABLE")) {
      std::cerr << "[gapbs] CXL graph is encrypted; set CXL_SEC_ENABLE=1 and configure CXL_SEC_MGR or CXL_SEC_KEY_HEX"
                << std::endl;
      std::exit(-136);
    }

    static const uint8_t kSecDirGraph = 3;
    static const uint8_t kRegionOutOffsets = 0;
    static const uint8_t kRegionOutNeigh = 1;
    static const uint8_t kRegionInOffsets = 2;
    static const uint8_t kRegionInNeigh = 3;

    gapbs::cxl_sec::Client sec;
    sec.InitFromEnvOrExit(reinterpret_cast<unsigned char*>(shm.base()));
    sec.WaitTableReadyOrExit(gapbs::cxl_sec::GetEnvU32("CXL_SEC_TIMEOUT_MS", 10000));

    const uint32_t local_id = gapbs::cxl_sec::GetEnvU32("CXL_SEC_NODE_ID", 1);
    const bool multi_key = !sec.uses_mgr() && ((h.flags & kFlagHasPublic) != 0) && (h.owner_id != 0);
    const bool use_public = multi_key && (local_id != h.owner_id);

    if (use_public) {
      if (h.pub_out_offsets_off == 0 || h.pub_out_neigh_off == 0) {
        std::cerr << "[gapbs] CXL graph public copy missing but required (owner_id=" << h.owner_id
                  << ", local_id=" << local_id << ")" << std::endl;
        std::exit(-137);
      }
      if (has_inverse && (h.pub_in_offsets_off == 0 || h.pub_in_neigh_off == 0)) {
        std::cerr << "[gapbs] CXL graph public inverse copy missing but required" << std::endl;
        std::exit(-138);
      }
    }

    const uint64_t out_offsets_off = use_public ? h.pub_out_offsets_off : h.out_offsets_off;
    const uint64_t out_neigh_off = use_public ? h.pub_out_neigh_off : h.out_neigh_off;
    const uint64_t in_offsets_off = use_public ? h.pub_in_offsets_off : h.in_offsets_off;
    const uint64_t in_neigh_off = use_public ? h.pub_in_neigh_off : h.in_neigh_off;

    auto get_key = [&](uint64_t off, uint64_t len, unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES]) {
      if (sec.uses_mgr()) {
        sec.GetKeyForRangeOrExit(off, len, out_key);
        return;
      }
      if (use_public) {
        sec.GetCommonKeyOrExit(out_key);
      } else {
        sec.GetVmKeyOrExit(out_key);
      }
    };

    pvector<SGOffset> out_offsets(nn + 1);
    std::memcpy(out_offsets.data(), mm + out_offsets_off, out_offsets_bytes);
    unsigned char key_out_offsets[crypto_stream_chacha20_ietf_KEYBYTES];
    get_key(out_offsets_off, out_offsets_bytes, key_out_offsets);
    gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_offsets.data()), out_offsets_bytes, kSecDirGraph,
                          kRegionOutOffsets, 0, key_out_offsets);

    unsigned char* base = reinterpret_cast<unsigned char*>(shm.base());
    DestID_* out_neigh_cipher = reinterpret_cast<DestID_*>(base + out_neigh_off);

    // Crypto mode (pre-shared key, no security manager): keep shared memory
    // encrypted and decrypt into TD-private memory. This avoids in-place
    // decryption that would otherwise materialize plaintext in the shared region.
    const bool crypto_mode = !sec.uses_mgr();
    if (crypto_mode) {
      const uint64_t delay_ns = gapbs::cxl_shm::ShmDelayNsFromEnv();
      auto copy_from_shm_with_delay = [&](void* dst, const void* src, size_t len) {
        if (delay_ns && len && gapbs::cxl_shm::PtrInCxlShm(src))
          gapbs::cxl_shm::ShmDelayForNs(delay_ns);
        std::memcpy(dst, src, len);
      };

      DestID_* out_neigh = new DestID_[out_entries];
      copy_from_shm_with_delay(out_neigh, out_neigh_cipher, out_neigh_bytes);
      unsigned char key_out_neigh[crypto_stream_chacha20_ietf_KEYBYTES];
      get_key(out_neigh_off, out_neigh_bytes, key_out_neigh);
      gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_neigh), out_neigh_bytes, kSecDirGraph, kRegionOutNeigh,
                            0, key_out_neigh);

      if (!directed) {
        decrypt_ms = (gapbs::cxl_shm::NowNs() - dec_t0) / 1000000ULL;
        DestID_** out_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(out_offsets, out_neigh);
        log_attach();
        return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh);
      }

      if (has_inverse) {
        const size_t in_offsets_bytes = (nn + 1) * sizeof(SGOffset);
        pvector<SGOffset> in_offsets(nn + 1);
        std::memcpy(in_offsets.data(), mm + in_offsets_off, in_offsets_bytes);
        unsigned char key_in_offsets[crypto_stream_chacha20_ietf_KEYBYTES];
        get_key(in_offsets_off, in_offsets_bytes, key_in_offsets);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_offsets.data()), in_offsets_bytes, kSecDirGraph,
                              kRegionInOffsets, 0, key_in_offsets);

        const size_t in_entries = static_cast<size_t>(in_offsets[n]);
        const size_t in_neigh_bytes = in_entries * static_cast<size_t>(h.dest_bytes);
        DestID_* in_neigh_cipher = reinterpret_cast<DestID_*>(base + in_neigh_off);
        DestID_* in_neigh = new DestID_[in_entries];
        copy_from_shm_with_delay(in_neigh, in_neigh_cipher, in_neigh_bytes);
        unsigned char key_in_neigh[crypto_stream_chacha20_ietf_KEYBYTES];
        get_key(in_neigh_off, in_neigh_bytes, key_in_neigh);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_neigh), in_neigh_bytes, kSecDirGraph, kRegionInNeigh,
                              0, key_in_neigh);

        decrypt_ms = (gapbs::cxl_shm::NowNs() - dec_t0) / 1000000ULL;
        DestID_** out_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(out_offsets, out_neigh);
        DestID_** in_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(in_offsets, in_neigh);
        log_attach();
        return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh, in_index, in_neigh);
      }

      decrypt_ms = (gapbs::cxl_shm::NowNs() - dec_t0) / 1000000ULL;
      DestID_** out_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(out_offsets, out_neigh);
      log_attach();
      return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh, nullptr, nullptr);
    }

    DestID_* out_neigh = out_neigh_cipher;

    // Secure mode (security manager / per-range keys): decrypt shared-memory
    // neighbor arrays in place, so benchmark access touches the shared memory
    // region and triggers CXL_SHM_DELAY_NS. This trades away
    // "encrypted-at-rest during compute" semantics.
    // Use a simple shared header flag to avoid multiple processes decrypting
    // the same range concurrently (XOR-based cipher would re-encrypt if applied twice).
    Header* hdr_mut = gapbs::cxl_graph::GetHeader();
    static const uint32_t kPrivDone = 1u << 0;
    static const uint32_t kPrivBusy = 1u << 1;
    static const uint32_t kPubDone = 1u << 2;
    static const uint32_t kPubBusy = 1u << 3;
    uint32_t* dec_state = &hdr_mut->reserved1;
    const uint32_t done_bit = use_public ? kPubDone : kPrivDone;
    const uint32_t busy_bit = use_public ? kPubBusy : kPrivBusy;
    const unsigned dec_timeout_ms = EnvU32Local("GAPBS_CXL_SECURE_DECRYPT_TIMEOUT_MS", 600000);

    auto decrypt_inplace_once = [&](std::function<void()> work) {
      unsigned waited_ms = 0;
      while (true) {
        uint32_t s = __atomic_load_n(dec_state, __ATOMIC_ACQUIRE);
        if (s & done_bit) return;
        if (!(s & busy_bit)) {
          uint32_t desired = s | busy_bit;
          if (!__atomic_compare_exchange_n(dec_state, &s, desired, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            continue;
          }
          // We own the decrypt slot for this copy.
          work();
          // Publish decrypted data + clear busy flag.
          while (true) {
            uint32_t cur = __atomic_load_n(dec_state, __ATOMIC_ACQUIRE);
            uint32_t next = (cur | done_bit) & ~busy_bit;
            if (__atomic_compare_exchange_n(dec_state, &cur, next, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
              return;
            }
          }
        }
        if (waited_ms >= dec_timeout_ms) {
          std::cerr << "[gapbs] Timeout waiting for in-place decryption (reserved1=" << s
                    << ", timeout_ms=" << dec_timeout_ms << ")" << std::endl;
          std::exit(-139);
        }
        usleep(1000);
        waited_ms++;
      }
    };

    decrypt_inplace_once([&]() {
      unsigned char key_out_neigh[crypto_stream_chacha20_ietf_KEYBYTES];
      get_key(out_neigh_off, out_neigh_bytes, key_out_neigh);
      gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_neigh), out_neigh_bytes, kSecDirGraph, kRegionOutNeigh,
                            0, key_out_neigh);
      if (has_inverse) {
        const size_t in_offsets_bytes = (nn + 1) * sizeof(SGOffset);
        pvector<SGOffset> in_offsets_tmp(nn + 1);
        std::memcpy(in_offsets_tmp.data(), mm + in_offsets_off, in_offsets_bytes);
        unsigned char key_in_offsets[crypto_stream_chacha20_ietf_KEYBYTES];
        get_key(in_offsets_off, in_offsets_bytes, key_in_offsets);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_offsets_tmp.data()), in_offsets_bytes, kSecDirGraph,
                              kRegionInOffsets, 0, key_in_offsets);
        const size_t in_entries_tmp = static_cast<size_t>(in_offsets_tmp[n]);
        const size_t in_neigh_bytes_tmp = in_entries_tmp * static_cast<size_t>(h.dest_bytes);
        DestID_* in_neigh_tmp = reinterpret_cast<DestID_*>(base + in_neigh_off);
        unsigned char key_in_neigh[crypto_stream_chacha20_ietf_KEYBYTES];
        get_key(in_neigh_off, in_neigh_bytes_tmp, key_in_neigh);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_neigh_tmp), in_neigh_bytes_tmp, kSecDirGraph,
                              kRegionInNeigh, 0, key_in_neigh);
      }
    });

    decrypt_ms = (gapbs::cxl_shm::NowNs() - dec_t0) / 1000000ULL;

    DestID_** out_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(out_offsets, out_neigh);

    if (!directed) {
      const uint64_t pt0 = gapbs::cxl_shm::NowNs();
      do_pretouch(out_neigh, out_neigh_bytes);
      pretouch_ms = (gapbs::cxl_shm::NowNs() - pt0) / 1000000ULL;
      log_attach();
      return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh);
    }

    if (has_inverse) {
      const size_t in_offsets_bytes = (nn + 1) * sizeof(SGOffset);
      pvector<SGOffset> in_offsets(nn + 1);
      const uint64_t dec2_t0 = gapbs::cxl_shm::NowNs();
      std::memcpy(in_offsets.data(), mm + in_offsets_off, in_offsets_bytes);
      unsigned char key_in_offsets[crypto_stream_chacha20_ietf_KEYBYTES];
      get_key(in_offsets_off, in_offsets_bytes, key_in_offsets);
      gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_offsets.data()), in_offsets_bytes, kSecDirGraph,
                            kRegionInOffsets, 0, key_in_offsets);
      decrypt_ms += (gapbs::cxl_shm::NowNs() - dec2_t0) / 1000000ULL;

      DestID_* in_neigh = reinterpret_cast<DestID_*>(base + in_neigh_off);

      DestID_** in_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(in_offsets, in_neigh);
      const size_t in_entries = static_cast<size_t>(in_offsets[n]);
      const size_t in_neigh_bytes = in_entries * static_cast<size_t>(h.dest_bytes);
      const uint64_t pt0 = gapbs::cxl_shm::NowNs();
      do_pretouch(out_neigh, out_neigh_bytes);
      do_pretouch(in_neigh, in_neigh_bytes);
      pretouch_ms = (gapbs::cxl_shm::NowNs() - pt0) / 1000000ULL;
      log_attach();
      return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh, in_index, in_neigh);
    }

    const uint64_t pt0 = gapbs::cxl_shm::NowNs();
    do_pretouch(out_neigh, out_neigh_bytes);
    pretouch_ms = (gapbs::cxl_shm::NowNs() - pt0) / 1000000ULL;
    log_attach();
    return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh, nullptr, nullptr);
#endif
  }

  CSRGraph<NodeID_, DestID_, invert> PublishToCxlShm(CSRGraph<NodeID_, DestID_, invert> g) {
    using gapbs::cxl_graph::Header;
    using gapbs::cxl_graph::kFlagDirected;
    using gapbs::cxl_graph::kFlagEncrypted;
    using gapbs::cxl_graph::kFlagHasPublic;
    using gapbs::cxl_graph::kFlagHasInverse;
    using gapbs::cxl_graph::kFlagWeighted;
    using gapbs::cxl_graph::kMagic;
    using gapbs::cxl_graph::kVersion;

    const bool publish_only = EnvEnabledLocal("GAPBS_CXL_PUBLISH_ONLY");
    const bool secure = gapbs::cxl_sec::EnvEnabled("CXL_SEC_ENABLE");
    const char* common_hex_env = std::getenv("CXL_SEC_COMMON_KEY_HEX");
    const char* mgr_env = std::getenv("CXL_SEC_MGR");
    const bool want_public = secure && (common_hex_env != nullptr) && (*common_hex_env != '\0') &&
                             (mgr_env == nullptr || *mgr_env == '\0');

    gapbs::cxl_graph::ResetRegion();
    gapbs::cxl_shm::Mapping& shm = gapbs::cxl_shm::Global();

    const int64_t n = g.num_nodes();
    const bool directed = g.directed();
    const bool weighted = !std::is_same<NodeID_, DestID_>::value;
    const bool has_inverse = directed && (g.in_index() != nullptr) && (g.in_neighbors() != nullptr);

    pvector<SGOffset> out_offsets = g.VertexOffsets(false);
    const size_t out_entries = static_cast<size_t>(out_offsets[n]);

    SGOffset* out_offsets_shm = shm.AllocArray<SGOffset>(static_cast<size_t>(n + 1), 64);
    std::memcpy(out_offsets_shm, out_offsets.data(), static_cast<size_t>(n + 1) * sizeof(SGOffset));

    DestID_* out_neigh_shm = shm.AllocArray<DestID_>(out_entries, 64);
    std::memcpy(out_neigh_shm, g.out_neighbors(), out_entries * sizeof(DestID_));

    SGOffset* in_offsets_shm = nullptr;
    DestID_* in_neigh_shm = nullptr;
    pvector<SGOffset> in_offsets;
    size_t in_entries = 0;
    if (has_inverse) {
      in_offsets = g.VertexOffsets(true);
      in_entries = static_cast<size_t>(in_offsets[n]);
      in_offsets_shm = shm.AllocArray<SGOffset>(static_cast<size_t>(n + 1), 64);
      std::memcpy(in_offsets_shm, in_offsets.data(), static_cast<size_t>(n + 1) * sizeof(SGOffset));
      in_neigh_shm = shm.AllocArray<DestID_>(in_entries, 64);
      std::memcpy(in_neigh_shm, g.in_neighbors(), in_entries * sizeof(DestID_));
    }

    SGOffset* pub_out_offsets_shm = nullptr;
    DestID_* pub_out_neigh_shm = nullptr;
    SGOffset* pub_in_offsets_shm = nullptr;
    DestID_* pub_in_neigh_shm = nullptr;
    if (want_public) {
      pub_out_offsets_shm = shm.AllocArray<SGOffset>(static_cast<size_t>(n + 1), 64);
      std::memcpy(pub_out_offsets_shm, out_offsets.data(), static_cast<size_t>(n + 1) * sizeof(SGOffset));
      pub_out_neigh_shm = shm.AllocArray<DestID_>(out_entries, 64);
      std::memcpy(pub_out_neigh_shm, g.out_neighbors(), out_entries * sizeof(DestID_));
      if (has_inverse) {
        pub_in_offsets_shm = shm.AllocArray<SGOffset>(static_cast<size_t>(n + 1), 64);
        std::memcpy(pub_in_offsets_shm, in_offsets.data(), static_cast<size_t>(n + 1) * sizeof(SGOffset));
        pub_in_neigh_shm = shm.AllocArray<DestID_>(in_entries, 64);
        std::memcpy(pub_in_neigh_shm, g.in_neighbors(), in_entries * sizeof(DestID_));
      }
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(shm.base());
    Header h;
    std::memset(&h, 0, sizeof(h));
    h.magic = kMagic;
    h.version = kVersion;
    h.flags = 0;
    if (directed) h.flags |= kFlagDirected;
    if (has_inverse) h.flags |= kFlagHasInverse;
    if (weighted) h.flags |= kFlagWeighted;
    if (secure) h.flags |= kFlagEncrypted;
    if (want_public) h.flags |= kFlagHasPublic;
    h.num_nodes = static_cast<uint64_t>(n);
    h.num_edges_directed = static_cast<uint64_t>(out_entries);
    h.dest_bytes = static_cast<uint32_t>(sizeof(DestID_));
    h.owner_id = secure ? static_cast<uint32_t>(EnvU32Local("CXL_SEC_NODE_ID", 1)) : 0;
    h.out_offsets_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(out_offsets_shm) - base);
    h.out_neigh_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(out_neigh_shm) - base);
    if (has_inverse) {
      h.in_offsets_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(in_offsets_shm) - base);
      h.in_neigh_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(in_neigh_shm) - base);
    }
    if (want_public) {
      h.pub_out_offsets_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pub_out_offsets_shm) - base);
      h.pub_out_neigh_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pub_out_neigh_shm) - base);
      if (has_inverse) {
        h.pub_in_offsets_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pub_in_offsets_shm) - base);
        h.pub_in_neigh_off = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pub_in_neigh_shm) - base);
      }
    }
    h.total_bytes = static_cast<uint64_t>(shm.used());
    h.ready = secure ? 0 : 1;
    gapbs::cxl_graph::Publish(h);

#ifdef GAPBS_CXL_SECURE
    if (secure) {
      static const uint8_t kSecDirGraph = 3;
      static const uint8_t kRegionOutOffsets = 0;
      static const uint8_t kRegionOutNeigh = 1;
      static const uint8_t kRegionInOffsets = 2;
      static const uint8_t kRegionInNeigh = 3;

      gapbs::cxl_sec::Client seccli;
      seccli.InitFromEnvOrExit(reinterpret_cast<unsigned char*>(shm.base()));
      seccli.WaitTableReadyOrExit(gapbs::cxl_sec::GetEnvU32("CXL_SEC_TIMEOUT_MS", 10000));

      const size_t out_offsets_bytes = (static_cast<size_t>(n) + 1) * sizeof(SGOffset);
      const size_t out_neigh_bytes = out_entries * sizeof(DestID_);

      if (seccli.uses_mgr()) {
        unsigned char key_out_offsets[crypto_stream_chacha20_ietf_KEYBYTES];
        seccli.GetKeyForRangeOrExit(h.out_offsets_off, out_offsets_bytes, key_out_offsets);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_offsets_shm), out_offsets_bytes, kSecDirGraph,
                              kRegionOutOffsets, 0, key_out_offsets);

        unsigned char key_out_neigh[crypto_stream_chacha20_ietf_KEYBYTES];
        seccli.GetKeyForRangeOrExit(h.out_neigh_off, out_neigh_bytes, key_out_neigh);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_neigh_shm), out_neigh_bytes, kSecDirGraph,
                              kRegionOutNeigh, 0, key_out_neigh);
      } else {
        unsigned char vm_key[crypto_stream_chacha20_ietf_KEYBYTES];
        seccli.GetVmKeyOrExit(vm_key);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_offsets_shm), out_offsets_bytes, kSecDirGraph,
                              kRegionOutOffsets, 0, vm_key);
        gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(out_neigh_shm), out_neigh_bytes, kSecDirGraph,
                              kRegionOutNeigh, 0, vm_key);

        if (want_public) {
          unsigned char common_key[crypto_stream_chacha20_ietf_KEYBYTES];
          seccli.GetCommonKeyOrExit(common_key);
          gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(pub_out_offsets_shm), out_offsets_bytes, kSecDirGraph,
                                kRegionOutOffsets, 0, common_key);
          gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(pub_out_neigh_shm), out_neigh_bytes, kSecDirGraph,
                                kRegionOutNeigh, 0, common_key);
        }
      }

      if (has_inverse) {
        const size_t in_offsets_bytes = (static_cast<size_t>(n) + 1) * sizeof(SGOffset);
        const size_t in_neigh_bytes = in_entries * sizeof(DestID_);

        if (seccli.uses_mgr()) {
          unsigned char key_in_offsets[crypto_stream_chacha20_ietf_KEYBYTES];
          seccli.GetKeyForRangeOrExit(h.in_offsets_off, in_offsets_bytes, key_in_offsets);
          gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_offsets_shm), in_offsets_bytes, kSecDirGraph,
                                kRegionInOffsets, 0, key_in_offsets);

          unsigned char key_in_neigh[crypto_stream_chacha20_ietf_KEYBYTES];
          seccli.GetKeyForRangeOrExit(h.in_neigh_off, in_neigh_bytes, key_in_neigh);
          gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_neigh_shm), in_neigh_bytes, kSecDirGraph,
                                kRegionInNeigh, 0, key_in_neigh);
        } else {
          unsigned char vm_key[crypto_stream_chacha20_ietf_KEYBYTES];
          seccli.GetVmKeyOrExit(vm_key);
          gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_offsets_shm), in_offsets_bytes, kSecDirGraph,
                                kRegionInOffsets, 0, vm_key);
          gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(in_neigh_shm), in_neigh_bytes, kSecDirGraph,
                                kRegionInNeigh, 0, vm_key);

          if (want_public) {
            unsigned char common_key[crypto_stream_chacha20_ietf_KEYBYTES];
            seccli.GetCommonKeyOrExit(common_key);
            gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(pub_in_offsets_shm), in_offsets_bytes, kSecDirGraph,
                                  kRegionInOffsets, 0, common_key);
            gapbs::cxl_sec::Crypt(reinterpret_cast<unsigned char*>(pub_in_neigh_shm), in_neigh_bytes, kSecDirGraph,
                                  kRegionInNeigh, 0, common_key);
          }
        }
      }

      Header h_done = h;
      h_done.ready = 1;
      gapbs::cxl_graph::Publish(h_done);
    }
#endif

    std::cerr << "[gapbs] CXL graph published: nodes=" << n << " out_entries=" << out_entries
              << " directed=" << (directed ? 1 : 0) << " inverse=" << (has_inverse ? 1 : 0)
              << " encrypted=" << (secure ? 1 : 0) << " total_bytes=" << h.total_bytes << std::endl;

    if (publish_only) {
      std::cerr << "[gapbs] GAPBS_CXL_PUBLISH_ONLY=1: publish done, exiting." << std::endl;
      std::exit(0);
    }

    if (secure) {
      // Shared-memory graph is encrypted-at-rest; keep computation on the local graph.
      return g;
    }

    DestID_** out_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(out_offsets, out_neigh_shm);
    if (!directed) {
      return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh_shm);
    }
    if (has_inverse) {
      DestID_** in_index = CSRGraph<NodeID_, DestID_, invert>::GenIndex(in_offsets, in_neigh_shm);
      return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh_shm, in_index, in_neigh_shm);
    }
    return CSRGraph<NodeID_, DestID_, invert>(n, out_index, out_neigh_shm, nullptr, nullptr);
  }
#endif

  DestID_ GetSource(EdgePair<NodeID_, NodeID_> e) {
    return e.u;
  }

  DestID_ GetSource(EdgePair<NodeID_, NodeWeight<NodeID_, WeightT_>> e) {
    return NodeWeight<NodeID_, WeightT_>(e.u, e.v.w);
  }

  NodeID_ FindMaxNodeID(const EdgeList &el) {
    NodeID_ max_seen = 0;
    #pragma omp parallel for reduction(max : max_seen)
    for (auto it = el.begin(); it < el.end(); it++) {
      Edge e = *it;
      max_seen = std::max(max_seen, e.u);
      max_seen = std::max(max_seen, (NodeID_) e.v);
    }
    return max_seen;
  }

  pvector<NodeID_> CountDegrees(const EdgeList &el, bool transpose) {
    pvector<NodeID_> degrees(num_nodes_, 0);
    #pragma omp parallel for
    for (auto it = el.begin(); it < el.end(); it++) {
      Edge e = *it;
      if (symmetrize_ || (!symmetrize_ && !transpose))
        fetch_and_add(degrees[e.u], 1);
      if ((symmetrize_ && !in_place_) || (!symmetrize_ && transpose))
        fetch_and_add(degrees[(NodeID_) e.v], 1);
    }
    return degrees;
  }

  static
  pvector<SGOffset> PrefixSum(const pvector<NodeID_> &degrees) {
    pvector<SGOffset> sums(degrees.size() + 1);
    SGOffset total = 0;
    for (size_t n=0; n < degrees.size(); n++) {
      sums[n] = total;
      total += degrees[n];
    }
    sums[degrees.size()] = total;
    return sums;
  }

  static
  pvector<SGOffset> ParallelPrefixSum(const pvector<NodeID_> &degrees) {
    const size_t block_size = 1<<20;
    const size_t num_blocks = (degrees.size() + block_size - 1) / block_size;
    pvector<SGOffset> local_sums(num_blocks);
    #pragma omp parallel for
    for (size_t block=0; block < num_blocks; block++) {
      SGOffset lsum = 0;
      size_t block_end = std::min((block + 1) * block_size, degrees.size());
      for (size_t i=block * block_size; i < block_end; i++)
        lsum += degrees[i];
      local_sums[block] = lsum;
    }
    pvector<SGOffset> bulk_prefix(num_blocks+1);
    SGOffset total = 0;
    for (size_t block=0; block < num_blocks; block++) {
      bulk_prefix[block] = total;
      total += local_sums[block];
    }
    bulk_prefix[num_blocks] = total;
    pvector<SGOffset> prefix(degrees.size() + 1);
    #pragma omp parallel for
    for (size_t block=0; block < num_blocks; block++) {
      SGOffset local_total = bulk_prefix[block];
      size_t block_end = std::min((block + 1) * block_size, degrees.size());
      for (size_t i=block * block_size; i < block_end; i++) {
        prefix[i] = local_total;
        local_total += degrees[i];
      }
    }
    prefix[degrees.size()] = bulk_prefix[num_blocks];
    return prefix;
  }

  // Removes self-loops and redundant edges
  // Side effect: neighbor IDs will be sorted
  void SquishCSR(const CSRGraph<NodeID_, DestID_, invert> &g, bool transpose,
                 DestID_*** sq_index, DestID_** sq_neighs) {
    pvector<NodeID_> diffs(g.num_nodes());
    DestID_ *n_start, *n_end;
    #pragma omp parallel for private(n_start, n_end)
    for (NodeID_ n=0; n < g.num_nodes(); n++) {
      if (transpose) {
        n_start = g.in_neigh(n).begin();
        n_end = g.in_neigh(n).end();
      } else {
        n_start = g.out_neigh(n).begin();
        n_end = g.out_neigh(n).end();
      }
      std::sort(n_start, n_end);
      DestID_ *new_end = std::unique(n_start, n_end);
      new_end = std::remove(n_start, new_end, n);
      diffs[n] = new_end - n_start;
    }
    pvector<SGOffset> sq_offsets = ParallelPrefixSum(diffs);
    *sq_neighs = new DestID_[sq_offsets[g.num_nodes()]];
    *sq_index = CSRGraph<NodeID_, DestID_>::GenIndex(sq_offsets, *sq_neighs);
    #pragma omp parallel for private(n_start)
    for (NodeID_ n=0; n < g.num_nodes(); n++) {
      if (transpose)
        n_start = g.in_neigh(n).begin();
      else
        n_start = g.out_neigh(n).begin();
      std::copy(n_start, n_start+diffs[n], (*sq_index)[n]);
    }
  }

  CSRGraph<NodeID_, DestID_, invert> SquishGraph(
      const CSRGraph<NodeID_, DestID_, invert> &g) {
    DestID_ **out_index, *out_neighs, **in_index, *in_neighs;
    SquishCSR(g, false, &out_index, &out_neighs);
    if (g.directed()) {
      if (invert)
        SquishCSR(g, true, &in_index, &in_neighs);
      return CSRGraph<NodeID_, DestID_, invert>(g.num_nodes(), out_index,
                                                out_neighs, in_index,
                                                in_neighs);
    } else {
      return CSRGraph<NodeID_, DestID_, invert>(g.num_nodes(), out_index,
                                                out_neighs);
    }
  }

  /*
  In-Place Graph Building Steps
    - sort edges and squish (remove self loops and redundant edges)
    - overwrite EdgeList's memory with outgoing neighbors
    - if graph not being symmetrized
      - finalize structures and make incoming structures if requested
    - if being symmetrized
      - search for needed inverses, make room for them, add them in place
  */
  void MakeCSRInPlace(EdgeList &el, DestID_*** index, DestID_** neighs,
                      DestID_*** inv_index, DestID_** inv_neighs) {
    // preprocess EdgeList - sort & squish in place
    std::sort(el.begin(), el.end());
    auto new_end = std::unique(el.begin(), el.end());
    el.resize(new_end - el.begin());
    auto self_loop = [](Edge e){ return e.u == e.v; };
    new_end = std::remove_if(el.begin(), el.end(), self_loop);
    el.resize(new_end - el.begin());
    // analyze EdgeList and repurpose it for outgoing edges
    pvector<NodeID_> degrees = CountDegrees(el, false);
    pvector<SGOffset> offsets = ParallelPrefixSum(degrees);
    pvector<NodeID_> indegrees = CountDegrees(el, true);
    *neighs = reinterpret_cast<DestID_*>(el.data());
    for (Edge e : el)
      (*neighs)[offsets[e.u]++] = e.v;
    size_t num_edges = el.size();
    el.leak();
    // revert offsets by shifting them down
    for (NodeID_ n = num_nodes_; n >= 0; n--)
      offsets[n] = n != 0 ? offsets[n-1] : 0;
    if (!symmetrize_) {   // not going to symmetrize so no need to add edges
      size_t new_size = num_edges * sizeof(DestID_);
      *neighs = static_cast<DestID_*>(std::realloc(*neighs, new_size));
      *index = CSRGraph<NodeID_, DestID_>::GenIndex(offsets, *neighs);
      if (invert) {       // create inv_neighs & inv_index for incoming edges
        pvector<SGOffset> inoffsets = ParallelPrefixSum(indegrees);
        *inv_neighs = new DestID_[inoffsets[num_nodes_]];
        *inv_index = CSRGraph<NodeID_, DestID_>::GenIndex(inoffsets,
                                                          *inv_neighs);
        for (NodeID_ u = 0; u < num_nodes_; u++) {
          for (DestID_* it = (*index)[u]; it < (*index)[u+1]; it++) {
            NodeID_ v = static_cast<NodeID_>(*it);
            (*inv_neighs)[inoffsets[v]] = u;
            inoffsets[v]++;
          }
        }
      }
    } else {              // symmetrize graph by adding missing inverse edges
      // Step 1 - count number of needed inverses
      pvector<NodeID_> invs_needed(num_nodes_, 0);
      for (NodeID_ u = 0; u < num_nodes_; u++) {
        for (SGOffset i = offsets[u]; i < offsets[u+1]; i++) {
          DestID_ v = (*neighs)[i];
          bool inv_found = std::binary_search(*neighs + offsets[v],
                                              *neighs + offsets[v+1],
                                              static_cast<DestID_>(u));
          if (!inv_found)
            invs_needed[v]++;
        }
      }
      // increase offsets to account for missing inverses, realloc neighs
      SGOffset total_missing_inv = 0;
      for (NodeID_ n = 0; n < num_nodes_; n++) {
        offsets[n] += total_missing_inv;
        total_missing_inv += invs_needed[n];
      }
      offsets[num_nodes_] += total_missing_inv;
      size_t newsize = (offsets[num_nodes_] * sizeof(DestID_));
      *neighs = static_cast<DestID_*>(std::realloc(*neighs, newsize));
      if (*neighs == nullptr) {
        std::cout << "Call to realloc() failed" << std::endl;
        exit(-33);
      }
      // Step 2 - spread out existing neighs to make room for inverses
      //   copies backwards (overwrites) and inserts free space at starts
      SGOffset tail_index = offsets[num_nodes_] - 1;
      for (NodeID_ n = num_nodes_ - 1; n >= 0; n--) {
        SGOffset new_start = offsets[n] + invs_needed[n];
        for (SGOffset i = offsets[n+1]-1; i >= new_start; i--) {
          (*neighs)[tail_index] = (*neighs)[i - total_missing_inv];
          tail_index--;
        }
        total_missing_inv -= invs_needed[n];
        tail_index -= invs_needed[n];
      }
      // Step 3 - add missing inverse edges into free spaces from Step 2
      for (NodeID_ u = 0; u < num_nodes_; u++) {
        for (SGOffset i = offsets[u] + invs_needed[u]; i < offsets[u+1]; i++) {
          DestID_ v = (*neighs)[i];
          bool inv_found = std::binary_search(
                             *neighs + offsets[v] + invs_needed[v],
                             *neighs + offsets[v+1],
                             static_cast<DestID_>(u));
          if (!inv_found) {
            (*neighs)[offsets[v] + invs_needed[v] -1] = static_cast<DestID_>(u);
            invs_needed[v]--;
          }
        }
      }
      for (NodeID_ n = 0; n < num_nodes_; n++)
        std::sort(*neighs + offsets[n], *neighs + offsets[n+1]);
      *index = CSRGraph<NodeID_, DestID_>::GenIndex(offsets, *neighs);
    }
  }

  /*
  Graph Building Steps (for CSR):
    - Read edgelist once to determine vertex degrees (CountDegrees)
    - Determine vertex offsets by a prefix sum (ParallelPrefixSum)
    - Allocate storage and set points according to offsets (GenIndex)
    - Copy edges into storage
  */
  void MakeCSR(const EdgeList &el, bool transpose, DestID_*** index,
               DestID_** neighs) {
    pvector<NodeID_> degrees = CountDegrees(el, transpose);
    pvector<SGOffset> offsets = ParallelPrefixSum(degrees);
    *neighs = new DestID_[offsets[num_nodes_]];
    *index = CSRGraph<NodeID_, DestID_>::GenIndex(offsets, *neighs);
    #pragma omp parallel for
    for (auto it = el.begin(); it < el.end(); it++) {
      Edge e = *it;
      if (symmetrize_ || (!symmetrize_ && !transpose))
        (*neighs)[fetch_and_add(offsets[e.u], 1)] = e.v;
      if (symmetrize_ || (!symmetrize_ && transpose))
        (*neighs)[fetch_and_add(offsets[static_cast<NodeID_>(e.v)], 1)] =
            GetSource(e);
    }
  }

  CSRGraph<NodeID_, DestID_, invert> MakeGraphFromEL(EdgeList &el) {
    DestID_ **index = nullptr, **inv_index = nullptr;
    DestID_ *neighs = nullptr, *inv_neighs = nullptr;
    Timer t;
    t.Start();
    if (num_nodes_ == -1)
      num_nodes_ = FindMaxNodeID(el)+1;
    if (needs_weights_)
      Generator<NodeID_, DestID_, WeightT_>::InsertWeights(el);
    if (in_place_) {
      MakeCSRInPlace(el, &index, &neighs, &inv_index, &inv_neighs);
    } else {
      MakeCSR(el, false, &index, &neighs);
      if (!symmetrize_ && invert) {
        MakeCSR(el, true, &inv_index, &inv_neighs);
      }
    }
    t.Stop();
    PrintTime("Build Time", t.Seconds());
    if (symmetrize_)
      return CSRGraph<NodeID_, DestID_, invert>(num_nodes_, index, neighs);
    else
      return CSRGraph<NodeID_, DestID_, invert>(num_nodes_, index, neighs,
                                                inv_index, inv_neighs);
  }

  CSRGraph<NodeID_, DestID_, invert> MakeGraph() {
#ifdef GAPBS_CXL_SHM
    // Multi-process/multi-host workflows may publish the graph once into shared
    // memory and have other processes attach to it.
    const CxlMode mode = GetCxlMode();
    if (mode == CxlMode::kAttach) {
      return LoadFromCxlShm();
    }
    if (mode == CxlMode::kAuto && gapbs::cxl_graph::Ready()) {
      return LoadFromCxlShm();
    }
#endif

    CSRGraph<NodeID_, DestID_, invert> g;
    bool serialized = false;
    {  // extra scope to trigger earlier deletion of el (save memory)
      EdgeList el;
      if (cli_.filename() != "") {
        Reader<NodeID_, DestID_, WeightT_, invert> r(cli_.filename());
        if ((r.GetSuffix() == ".sg") || (r.GetSuffix() == ".wsg")) {
          g = r.ReadSerializedGraph();
          serialized = true;
        } else {
          el = r.ReadFile(needs_weights_);
        }
      } else if (cli_.scale() != -1) {
        Generator<NodeID_, DestID_> gen(cli_.scale(), cli_.degree());
        el = gen.GenerateEL(cli_.uniform());
      }
      if (!serialized)
        g = MakeGraphFromEL(el);
    }
    if (!in_place_ && !serialized)
      g = SquishGraph(g);
#ifdef GAPBS_CXL_SHM
    return PublishToCxlShm(std::move(g));
#else
    return g;
#endif
  }

  // Relabels (and rebuilds) graph by order of decreasing degree
  static
  CSRGraph<NodeID_, DestID_, invert> RelabelByDegree(
      const CSRGraph<NodeID_, DestID_, invert> &g) {
    if (g.directed()) {
      std::cout << "Cannot relabel directed graph" << std::endl;
      std::exit(-11);
    }
    Timer t;
    t.Start();
    typedef std::pair<int64_t, NodeID_> degree_node_p;
    pvector<degree_node_p> degree_id_pairs(g.num_nodes());
    #pragma omp parallel for
    for (NodeID_ n=0; n < g.num_nodes(); n++)
      degree_id_pairs[n] = std::make_pair(g.out_degree(n), n);
    std::sort(degree_id_pairs.begin(), degree_id_pairs.end(),
              std::greater<degree_node_p>());
    pvector<NodeID_> degrees(g.num_nodes());
    pvector<NodeID_> new_ids(g.num_nodes());
    #pragma omp parallel for
    for (NodeID_ n=0; n < g.num_nodes(); n++) {
      degrees[n] = degree_id_pairs[n].first;
      new_ids[degree_id_pairs[n].second] = n;
    }
    pvector<SGOffset> offsets = ParallelPrefixSum(degrees);
    DestID_* neighs = new DestID_[offsets[g.num_nodes()]];
    DestID_** index = CSRGraph<NodeID_, DestID_>::GenIndex(offsets, neighs);
    #pragma omp parallel for
    for (NodeID_ u=0; u < g.num_nodes(); u++) {
      for (NodeID_ v : g.out_neigh(u))
        neighs[offsets[new_ids[u]]++] = new_ids[v];
      std::sort(index[new_ids[u]], index[new_ids[u]+1]);
    }
    t.Stop();
    PrintTime("Relabel", t.Seconds());
    return CSRGraph<NodeID_, DestID_, invert>(g.num_nodes(), index, neighs);
  }
};

#endif  // BUILDER_H_
