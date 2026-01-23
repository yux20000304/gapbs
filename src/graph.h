// Copyright (c) 2015, The Regents of the University of California (Regents)
// See LICENSE.txt for license details

#ifndef GRAPH_H_
#define GRAPH_H_

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <type_traits>

#include "pvector.h"
#include "util.h"

#ifdef GAPBS_CXL_SHM
#include "cxl_shm.h"
#endif
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
#include "cxl_sec.h"
#endif


/*
GAP Benchmark Suite
Class:  CSRGraph
Author: Scott Beamer

Simple container for graph in CSR format
 - Intended to be constructed by a Builder
 - To make weighted, set DestID_ template type to NodeWeight
 - MakeInverse parameter controls whether graph stores incoming edges
*/


// Used to hold node & weight, with another node it makes a weighted edge
template <typename NodeID_, typename WeightT_>
struct NodeWeight {
  NodeID_ v;
  WeightT_ w;
  NodeWeight() {}
  NodeWeight(NodeID_ v) : v(v), w(1) {}
  NodeWeight(NodeID_ v, WeightT_ w) : v(v), w(w) {}

  bool operator< (const NodeWeight& rhs) const {
    return v == rhs.v ? w < rhs.w : v < rhs.v;
  }

  // doesn't check WeightT_s, needed to remove duplicate edges
  bool operator== (const NodeWeight& rhs) const {
    return v == rhs.v;
  }

  // doesn't check WeightT_s, needed to remove self edges
  bool operator== (const NodeID_& rhs) const {
    return v == rhs;
  }

  operator NodeID_() {
    return v;
  }
};

template <typename NodeID_, typename WeightT_>
std::ostream& operator<<(std::ostream& os,
                         const NodeWeight<NodeID_, WeightT_>& nw) {
  os << nw.v << " " << nw.w;
  return os;
}

template <typename NodeID_, typename WeightT_>
std::istream& operator>>(std::istream& is, NodeWeight<NodeID_, WeightT_>& nw) {
  is >> nw.v >> nw.w;
  return is;
}



// Syntactic sugar for an edge
template <typename SrcT, typename DstT = SrcT>
struct EdgePair {
  SrcT u;
  DstT v;

  EdgePair() {}

  EdgePair(SrcT u, DstT v) : u(u), v(v) {}

  bool operator< (const EdgePair& rhs) const {
    return u == rhs.u ? v < rhs.v : u < rhs.u;
  }

  bool operator== (const EdgePair& rhs) const {
    return (u == rhs.u) && (v == rhs.v);
  }
};

// SG = serialized graph, these types are for writing graph to file
typedef int32_t SGID;
typedef EdgePair<SGID> SGEdge;
typedef int64_t SGOffset;



template <class NodeID_, class DestID_ = NodeID_, bool MakeInverse = true>
class CSRGraph {
  // Used for *non-negative* offsets within a neighborhood
  typedef std::make_unsigned<std::ptrdiff_t>::type OffsetT;

  // Used to access neighbors of vertex, basically sugar for iterators
  class Neighborhood {
    std::unique_ptr<DestID_[]> owned_;
    DestID_* begin_;
    DestID_* end_;
   public:
    typedef DestID_* iterator;

    Neighborhood(DestID_* begin, DestID_* end) : begin_(begin), end_(end) {}

    Neighborhood(std::unique_ptr<DestID_[]> owned, DestID_* begin, DestID_* end)
        : owned_(std::move(owned)), begin_(begin), end_(end) {}

    Neighborhood(const Neighborhood&) = delete;
    Neighborhood& operator=(const Neighborhood&) = delete;
    Neighborhood(Neighborhood&&) = default;
    Neighborhood& operator=(Neighborhood&&) = default;

    iterator begin() { return begin_; }
    iterator end() { return end_; }
  };

  void ReleaseResources() {
    if (out_index_ != nullptr)
      delete[] out_index_;
#ifdef GAPBS_CXL_SHM
    if (out_neighbors_ != nullptr && !gapbs::cxl_shm::PtrInCxlShm(out_neighbors_))
      delete[] out_neighbors_;
#else
    if (out_neighbors_ != nullptr)
      delete[] out_neighbors_;
#endif
    if (directed_) {
      if (in_index_ != nullptr)
        delete[] in_index_;
#ifdef GAPBS_CXL_SHM
      if (in_neighbors_ != nullptr && !gapbs::cxl_shm::PtrInCxlShm(in_neighbors_))
        delete[] in_neighbors_;
#else
      if (in_neighbors_ != nullptr)
        delete[] in_neighbors_;
#endif
    }
  }


 public:
  CSRGraph() : directed_(false), num_nodes_(-1), num_edges_(-1),
    out_index_(nullptr), out_neighbors_(nullptr),
    in_index_(nullptr), in_neighbors_(nullptr)
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    ,
    cxl_crypto_lazy_(false),
    cxl_has_in_key_(false),
    cxl_dir_(0),
    cxl_region_out_(0),
    cxl_region_in_(0),
    cxl_seq_(0)
#endif
  {
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    std::memset(cxl_key_out_, 0, sizeof(cxl_key_out_));
    std::memset(cxl_key_in_, 0, sizeof(cxl_key_in_));
#endif
  }

  CSRGraph(int64_t num_nodes, DestID_** index, DestID_* neighs) :
    directed_(false), num_nodes_(num_nodes),
    out_index_(index), out_neighbors_(neighs),
    in_index_(index), in_neighbors_(neighs)
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    ,
    cxl_crypto_lazy_(false),
    cxl_has_in_key_(false),
    cxl_dir_(0),
    cxl_region_out_(0),
    cxl_region_in_(0),
    cxl_seq_(0)
#endif
  {
      num_edges_ = (out_index_[num_nodes_] - out_index_[0]) / 2;
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
      std::memset(cxl_key_out_, 0, sizeof(cxl_key_out_));
      std::memset(cxl_key_in_, 0, sizeof(cxl_key_in_));
#endif
    }

  CSRGraph(int64_t num_nodes, DestID_** out_index, DestID_* out_neighs,
        DestID_** in_index, DestID_* in_neighs) :
    directed_(true), num_nodes_(num_nodes),
    out_index_(out_index), out_neighbors_(out_neighs),
    in_index_(in_index), in_neighbors_(in_neighs)
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    ,
    cxl_crypto_lazy_(false),
    cxl_has_in_key_(false),
    cxl_dir_(0),
    cxl_region_out_(0),
    cxl_region_in_(0),
    cxl_seq_(0)
#endif
  {
      num_edges_ = out_index_[num_nodes_] - out_index_[0];
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
      std::memset(cxl_key_out_, 0, sizeof(cxl_key_out_));
      std::memset(cxl_key_in_, 0, sizeof(cxl_key_in_));
#endif
    }

  CSRGraph(CSRGraph&& other) : directed_(other.directed_),
    num_nodes_(other.num_nodes_), num_edges_(other.num_edges_),
    out_index_(other.out_index_), out_neighbors_(other.out_neighbors_),
    in_index_(other.in_index_), in_neighbors_(other.in_neighbors_)
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    ,
    cxl_crypto_lazy_(other.cxl_crypto_lazy_),
    cxl_has_in_key_(other.cxl_has_in_key_),
    cxl_dir_(other.cxl_dir_),
    cxl_region_out_(other.cxl_region_out_),
    cxl_region_in_(other.cxl_region_in_),
    cxl_seq_(other.cxl_seq_)
#endif
  {
      other.num_edges_ = -1;
      other.num_nodes_ = -1;
      other.out_index_ = nullptr;
      other.out_neighbors_ = nullptr;
      other.in_index_ = nullptr;
      other.in_neighbors_ = nullptr;
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
      std::memcpy(cxl_key_out_, other.cxl_key_out_, sizeof(cxl_key_out_));
      std::memcpy(cxl_key_in_, other.cxl_key_in_, sizeof(cxl_key_in_));
      other.cxl_crypto_lazy_ = false;
      other.cxl_has_in_key_ = false;
      std::memset(other.cxl_key_out_, 0, sizeof(other.cxl_key_out_));
      std::memset(other.cxl_key_in_, 0, sizeof(other.cxl_key_in_));
#endif
  }

  ~CSRGraph() {
    ReleaseResources();
  }

  CSRGraph& operator=(CSRGraph&& other) {
    if (this != &other) {
      ReleaseResources();
      directed_ = other.directed_;
      num_edges_ = other.num_edges_;
      num_nodes_ = other.num_nodes_;
      out_index_ = other.out_index_;
      out_neighbors_ = other.out_neighbors_;
      in_index_ = other.in_index_;
      in_neighbors_ = other.in_neighbors_;
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
      cxl_crypto_lazy_ = other.cxl_crypto_lazy_;
      cxl_has_in_key_ = other.cxl_has_in_key_;
      cxl_dir_ = other.cxl_dir_;
      cxl_region_out_ = other.cxl_region_out_;
      cxl_region_in_ = other.cxl_region_in_;
      cxl_seq_ = other.cxl_seq_;
      std::memcpy(cxl_key_out_, other.cxl_key_out_, sizeof(cxl_key_out_));
      std::memcpy(cxl_key_in_, other.cxl_key_in_, sizeof(cxl_key_in_));
#endif
      other.num_edges_ = -1;
      other.num_nodes_ = -1;
      other.out_index_ = nullptr;
      other.out_neighbors_ = nullptr;
      other.in_index_ = nullptr;
      other.in_neighbors_ = nullptr;
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
      other.cxl_crypto_lazy_ = false;
      other.cxl_has_in_key_ = false;
      std::memset(other.cxl_key_out_, 0, sizeof(other.cxl_key_out_));
      std::memset(other.cxl_key_in_, 0, sizeof(other.cxl_key_in_));
#endif
    }
    return *this;
  }

  bool directed() const {
    return directed_;
  }

  int64_t num_nodes() const {
    return num_nodes_;
  }

  int64_t num_edges() const {
    return num_edges_;
  }

  int64_t num_edges_directed() const {
    return directed_ ? num_edges_ : 2*num_edges_;
  }

  int64_t out_degree(NodeID_ v) const {
    return out_index_[v+1] - out_index_[v];
  }

  int64_t in_degree(NodeID_ v) const {
    static_assert(MakeInverse, "Graph inversion disabled but reading inverse");
    return in_index_[v+1] - in_index_[v];
  }

  Neighborhood out_neigh(NodeID_ n, OffsetT start_offset = 0) const {
#ifdef GAPBS_CXL_SHM
    gapbs::cxl_shm::ShmDelayMaybe(out_neighbors_);
#endif
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    if (cxl_crypto_lazy_) {
      DestID_* cipher_begin = out_index_[n];
      DestID_* cipher_end = out_index_[n + 1];
      OffsetT deg = static_cast<OffsetT>(cipher_end - cipher_begin);
      OffsetT so = std::min(start_offset, deg);
      if (deg == 0) {
        return Neighborhood(cipher_begin, cipher_begin);
      }
      std::unique_ptr<DestID_[]> buf(new DestID_[static_cast<size_t>(deg)]);
      std::memcpy(buf.get(), cipher_begin, static_cast<size_t>(deg) * sizeof(DestID_));
      const uint64_t byte_off = static_cast<uint64_t>(cipher_begin - out_neighbors_) * sizeof(DestID_);
      gapbs::cxl_sec::CryptAtOffset(reinterpret_cast<unsigned char*>(buf.get()),
                                    static_cast<size_t>(deg) * sizeof(DestID_),
                                    cxl_dir_, cxl_region_out_, cxl_seq_,
                                    byte_off, cxl_key_out_);
      DestID_* begin = buf.get() + so;
      DestID_* end = buf.get() + deg;
      return Neighborhood(std::move(buf), begin, end);
    }
#endif
    DestID_* begin = out_index_[n];
    DestID_* end = out_index_[n + 1];
    OffsetT deg = static_cast<OffsetT>(end - begin);
    OffsetT so = std::min(start_offset, deg);
    return Neighborhood(begin + so, end);
  }

  Neighborhood in_neigh(NodeID_ n, OffsetT start_offset = 0) const {
    static_assert(MakeInverse, "Graph inversion disabled but reading inverse");
#ifdef GAPBS_CXL_SHM
    gapbs::cxl_shm::ShmDelayMaybe(in_neighbors_);
#endif
#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
    if (!directed_) {
      return out_neigh(n, start_offset);
    }
    if (cxl_crypto_lazy_) {
      DestID_* cipher_begin = in_index_[n];
      DestID_* cipher_end = in_index_[n + 1];
      OffsetT deg = static_cast<OffsetT>(cipher_end - cipher_begin);
      OffsetT so = std::min(start_offset, deg);
      if (deg == 0) {
        return Neighborhood(cipher_begin, cipher_begin);
      }
      // If inverse key isn't configured (e.g., no inverse region), fall back to raw view.
      if (!cxl_has_in_key_ || in_neighbors_ == nullptr) {
        return Neighborhood(cipher_begin + so, cipher_end);
      }
      std::unique_ptr<DestID_[]> buf(new DestID_[static_cast<size_t>(deg)]);
      std::memcpy(buf.get(), cipher_begin, static_cast<size_t>(deg) * sizeof(DestID_));
      const uint64_t byte_off = static_cast<uint64_t>(cipher_begin - in_neighbors_) * sizeof(DestID_);
      gapbs::cxl_sec::CryptAtOffset(reinterpret_cast<unsigned char*>(buf.get()),
                                    static_cast<size_t>(deg) * sizeof(DestID_),
                                    cxl_dir_, cxl_region_in_, cxl_seq_,
                                    byte_off, cxl_key_in_);
      DestID_* begin = buf.get() + so;
      DestID_* end = buf.get() + deg;
      return Neighborhood(std::move(buf), begin, end);
    }
#endif
    DestID_* begin = in_index_[n];
    DestID_* end = in_index_[n + 1];
    OffsetT deg = static_cast<OffsetT>(end - begin);
    OffsetT so = std::min(start_offset, deg);
    return Neighborhood(begin + so, end);
  }

  void PrintStats() const {
    std::cout << "Graph has " << num_nodes_ << " nodes and "
              << num_edges_ << " ";
    if (!directed_)
      std::cout << "un";
    std::cout << "directed edges for degree: ";
    std::cout << num_edges_/num_nodes_ << std::endl;
  }

  void PrintTopology() const {
    for (NodeID_ i=0; i < num_nodes_; i++) {
      std::cout << i << ": ";
      for (DestID_ j : out_neigh(i)) {
        std::cout << j << " ";
      }
      std::cout << std::endl;
    }
  }

  const DestID_* out_neighbors() const { return out_neighbors_; }
  const DestID_* in_neighbors() const { return in_neighbors_; }
  DestID_** out_index() const { return out_index_; }
  DestID_** in_index() const { return in_index_; }

#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
  void EnableCxlCryptoLazy(uint8_t direction, uint8_t out_region_id,
                           const unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES],
                           uint8_t in_region_id,
                           const unsigned char in_key[crypto_stream_chacha20_ietf_KEYBYTES],
                           uint64_t seq = 0) {
    cxl_crypto_lazy_ = true;
    cxl_has_in_key_ = true;
    cxl_dir_ = direction;
    cxl_region_out_ = out_region_id;
    cxl_region_in_ = in_region_id;
    cxl_seq_ = seq;
    std::memcpy(cxl_key_out_, out_key, sizeof(cxl_key_out_));
    std::memcpy(cxl_key_in_, in_key, sizeof(cxl_key_in_));
  }

  void EnableCxlCryptoLazyOutOnly(uint8_t direction, uint8_t out_region_id,
                                  const unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES],
                                  uint64_t seq = 0) {
    cxl_crypto_lazy_ = true;
    cxl_has_in_key_ = false;
    cxl_dir_ = direction;
    cxl_region_out_ = out_region_id;
    cxl_region_in_ = 0;
    cxl_seq_ = seq;
    std::memcpy(cxl_key_out_, out_key, sizeof(cxl_key_out_));
    std::memset(cxl_key_in_, 0, sizeof(cxl_key_in_));
  }
#endif

  static DestID_** GenIndex(const pvector<SGOffset> &offsets, DestID_* neighs) {
    NodeID_ length = offsets.size();
    DestID_** index = new DestID_*[length];
    #pragma omp parallel for
    for (NodeID_ n=0; n < length; n++)
      index[n] = neighs + offsets[n];
    return index;
  }

  pvector<SGOffset> VertexOffsets(bool in_graph = false) const {
    pvector<SGOffset> offsets(num_nodes_+1);
    for (NodeID_ n=0; n < num_nodes_+1; n++)
      if (in_graph)
        offsets[n] = in_index_[n] - in_index_[0];
      else
        offsets[n] = out_index_[n] - out_index_[0];
    return offsets;
  }

  Range<NodeID_> vertices() const {
    return Range<NodeID_>(num_nodes());
  }

 private:
  bool directed_;
  int64_t num_nodes_;
  int64_t num_edges_;
  DestID_** out_index_;
  DestID_*  out_neighbors_;
  DestID_** in_index_;
  DestID_*  in_neighbors_;

#if defined(GAPBS_CXL_SHM) && defined(GAPBS_CXL_SECURE)
  bool cxl_crypto_lazy_;
  bool cxl_has_in_key_;
  uint8_t cxl_dir_;
  uint8_t cxl_region_out_;
  uint8_t cxl_region_in_;
  uint64_t cxl_seq_;
  unsigned char cxl_key_out_[crypto_stream_chacha20_ietf_KEYBYTES];
  unsigned char cxl_key_in_[crypto_stream_chacha20_ietf_KEYBYTES];
#endif
};

#endif  // GRAPH_H_
