// SPDX-License-Identifier: BSD-3-Clause
//
// GAPBS CXL "secure shared memory" helper.
//
// This file is NOT part of upstream GAPBS. It mirrors the cxl-sec-dsm-sim
// "secure ring" design used for Redis:
// - A security manager process (cxl_sec_mgr) initializes an ACL+key table in
//   the shared memory mapping and serves access requests over TCP.
// - Clients request access (principal added to table entry), then use the
//   per-region key to encrypt/decrypt the shared-memory payload.
//
// Note: This is a benchmarking/security-modeling mechanism. It is not a full
// cryptographic design (e.g., keys currently live in shared memory).

#ifndef GAPBS_CXL_SEC_H_
#define GAPBS_CXL_SEC_H_

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <string>

#ifdef GAPBS_CXL_SECURE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sodium.h>

namespace gapbs {
namespace cxl_sec {

static const size_t kTableOffset = 512;
static const char kTableMagic[8] = {'C', 'X', 'L', 'S', 'E', 'C', '1', '\0'};
static const uint32_t kTableVersion = 1;
static const uint32_t kMaxEntries = 16;
static const uint32_t kMaxPrincipals = 16;

static const uint32_t kProtoMagic = 0x43534543u;  // 'CSEC'
static const uint16_t kProtoVersion = 1;
static const uint16_t kReqAccess = 1;

static const uint16_t kStatusOk = 0;

inline bool ParseKeyHex(const std::string& hex,
                        unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES]) {
  if (hex.empty())
    return false;
  size_t bin_len = 0;
  if (sodium_hex2bin(out_key, crypto_stream_chacha20_ietf_KEYBYTES, hex.c_str(), hex.size(), nullptr, &bin_len,
                     nullptr) != 0) {
    return false;
  }
  return bin_len == crypto_stream_chacha20_ietf_KEYBYTES;
}

struct Entry {
  uint64_t start_off;
  uint64_t end_off;
  unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES];
  uint32_t principal_count;
  uint32_t reserved;
  uint64_t principals[kMaxPrincipals];
};

struct Table {
  char magic[8];
  uint32_t version;
  uint32_t entry_count;
  Entry entries[kMaxEntries];
};

struct Req {
  uint32_t magic_be;
  uint16_t version_be;
  uint16_t type_be;
  uint64_t principal_be;
  uint64_t offset_be;
  uint32_t length_be;
  uint32_t reserved_be;
};

struct Resp {
  uint32_t magic_be;
  uint16_t version_be;
  uint16_t status_be;
  uint32_t reserved_be;
};

inline bool EnvEnabled(const char* key) {
  const char* v = std::getenv(key);
  return v && *v && *v != '0';
}

inline unsigned GetEnvU32(const char* key, unsigned def) {
  const char* v = std::getenv(key);
  if (!v || !*v) return def;
  return static_cast<unsigned>(std::strtoul(v, nullptr, 0));
}

inline std::string GetEnvStr(const char* key) {
  const char* v = std::getenv(key);
  return (v && *v) ? std::string(v) : std::string();
}

inline int ParseHostPort(const std::string& s, std::string* host_out, std::string* port_out) {
  size_t pos = s.rfind(':');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= s.size()) return -1;
  *host_out = s.substr(0, pos);
  *port_out = s.substr(pos + 1);
  return 0;
}

inline int SocketConnect(const std::string& host, const std::string& port) {
  struct addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo* res = nullptr;
  int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
  if (rc != 0) return -1;

  int fd = -1;
  for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }

  freeaddrinfo(res);
  if (fd < 0) return -1;

  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  return fd;
}

inline ssize_t ReadFull(int fd, void* buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, static_cast<unsigned char*>(buf) + off, n - off);
    if (r == 0) return static_cast<ssize_t>(off);
    if (r < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += static_cast<size_t>(r);
  }
  return static_cast<ssize_t>(off);
}

inline int WriteFull(int fd, const void* buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, static_cast<const unsigned char*>(buf) + off, n - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += static_cast<size_t>(w);
  }
  return 0;
}

inline void Crypt(unsigned char* buf, size_t len, uint8_t direction, uint8_t region_id, uint64_t seq,
                  const unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES]) {
  unsigned char nonce[crypto_stream_chacha20_ietf_NONCEBYTES];
  std::memset(nonce, 0, sizeof(nonce));
  nonce[0] = direction;
  nonce[1] = region_id;
  std::memcpy(nonce + 4, &seq, sizeof(seq));
  crypto_stream_chacha20_ietf_xor(buf, buf, static_cast<unsigned long long>(len), nonce, key);
}

class Client {
 public:
  Client()
      : enabled_(false),
        use_mgr_(false),
        has_common_key_(false),
        base_(nullptr),
        fd_(-1),
        node_id_(0),
        principal_(0) {
    std::memset(psk_key_, 0, sizeof(psk_key_));
    std::memset(common_key_, 0, sizeof(common_key_));
  }

  ~Client() {
    if (fd_ >= 0) close(fd_);
  }

  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  bool enabled() const { return enabled_; }
  bool uses_mgr() const { return use_mgr_; }
  bool has_common_key() const { return has_common_key_; }
  uint64_t principal() const { return principal_; }

  void InitFromEnvOrExit(unsigned char* base) {
    base_ = base;
    if (!EnvEnabled("CXL_SEC_ENABLE")) return;

    node_id_ = GetEnvU32("CXL_SEC_NODE_ID", 1);
    principal_ = (static_cast<uint64_t>(node_id_) << 32) | static_cast<uint32_t>(getpid());

    if (sodium_init() < 0) {
      std::cerr << "[gapbs] sodium_init failed" << std::endl;
      std::exit(-122);
    }

    std::string key_hex = GetEnvStr("CXL_SEC_KEY_HEX");
    if (!key_hex.empty()) {
      if (!ParseKeyHex(key_hex, psk_key_)) {
        std::cerr << "[gapbs] Invalid CXL_SEC_KEY_HEX (expected "
                  << crypto_stream_chacha20_ietf_KEYBYTES << " bytes hex)" << std::endl;
        std::exit(-123);
      }
      std::string common_hex = GetEnvStr("CXL_SEC_COMMON_KEY_HEX");
      if (!common_hex.empty()) {
        if (!ParseKeyHex(common_hex, common_key_)) {
          std::cerr << "[gapbs] Invalid CXL_SEC_COMMON_KEY_HEX (expected "
                    << crypto_stream_chacha20_ietf_KEYBYTES << " bytes hex)" << std::endl;
          std::exit(-123);
        }
        has_common_key_ = true;
      } else {
        has_common_key_ = false;
      }
      enabled_ = true;
      use_mgr_ = false;
      return;
    }

    std::string mgr = GetEnvStr("CXL_SEC_MGR");
    if (mgr.empty()) {
      std::cerr << "[gapbs] CXL_SEC_ENABLE=1 requires either CXL_SEC_KEY_HEX=<hex> or CXL_SEC_MGR=<ip:port>"
                << std::endl;
      std::exit(-124);
    }

    std::string host, port;
    if (ParseHostPort(mgr, &host, &port) != 0) {
      std::cerr << "[gapbs] Invalid CXL_SEC_MGR: '" << mgr << "'" << std::endl;
      std::exit(-125);
    }

    int fd = SocketConnect(host, port);
    if (fd < 0) {
      std::cerr << "[gapbs] Failed to connect CXL_SEC_MGR=" << mgr << ": " << std::strerror(errno)
                << std::endl;
      std::exit(-126);
    }

    fd_ = fd;
    enabled_ = true;
    use_mgr_ = true;
    has_common_key_ = false;
  }

  void WaitTableReadyOrExit(unsigned timeout_ms) {
    if (!enabled_ || !use_mgr_) return;
    unsigned waited = 0;
    while (waited < timeout_ms) {
      Table* t = table();
      if (t && std::memcmp(t->magic, kTableMagic, 8) == 0 && t->version == kTableVersion) return;
      usleep(10 * 1000);
      waited += 10;
    }
    std::cerr << "[gapbs] timeout waiting for CXL sec table (offset=" << kTableOffset << ")"
              << std::endl;
    std::exit(-127);
  }

  const Entry* FindEntry(uint64_t off, uint64_t len) const {
    if (!enabled_ || !use_mgr_ || !base_ || len == 0) return nullptr;
    uint64_t end = off + len;
    if (end < off) return nullptr;
    const Table* t = table();
    if (!t) return nullptr;
    if (std::memcmp(t->magic, kTableMagic, 8) != 0 || t->version != kTableVersion) return nullptr;

    uint32_t n = t->entry_count;
    if (n > kMaxEntries) n = kMaxEntries;
    for (uint32_t i = 0; i < n; i++) {
      const Entry* e = &t->entries[i];
      if (off >= e->start_off && end <= e->end_off) return e;
    }
    return nullptr;
  }

  bool EntryHasPrincipal(const Entry* e) const {
    if (!e) return false;
    uint32_t n = e->principal_count;
    if (n > kMaxPrincipals) n = kMaxPrincipals;
    for (uint32_t i = 0; i < n; i++) {
      if (e->principals[i] == principal_) return true;
    }
    return false;
  }

  int RequestAccess(uint64_t off, uint32_t len) {
    if (!enabled_ || !use_mgr_ || fd_ < 0) return -1;
    Req req;
    std::memset(&req, 0, sizeof(req));
    req.magic_be = htonl(kProtoMagic);
    req.version_be = htons(kProtoVersion);
    req.type_be = htons(kReqAccess);
    req.principal_be = htobe64(principal_);
    req.offset_be = htobe64(off);
    req.length_be = htonl(len);

    if (WriteFull(fd_, &req, sizeof(req)) != 0) return -1;

    Resp resp;
    ssize_t r = ReadFull(fd_, &resp, sizeof(resp));
    if (r != static_cast<ssize_t>(sizeof(resp))) return -1;

    uint32_t magic = ntohl(resp.magic_be);
    uint16_t ver = ntohs(resp.version_be);
    uint16_t status = ntohs(resp.status_be);
    if (magic != kProtoMagic || ver != kProtoVersion || status != kStatusOk) return -1;
    return 0;
  }

  void EnsureAccessOrExit(uint64_t off, uint64_t len) {
    if (!enabled_ || !use_mgr_) return;
    for (int tries = 0; tries < 3; tries++) {
      const Entry* e = FindEntry(off, len);
      if (!e) break;
      if (EntryHasPrincipal(e)) return;
      if (RequestAccess(off, static_cast<uint32_t>(len > 0xffffffffu ? 0xffffffffu : len)) != 0) break;
      usleep(1000);
    }
    std::cerr << "[gapbs] CXL sec: access denied for region off=" << off << " len=" << len << std::endl;
    std::exit(-128);
  }

  void GetKeyForRangeOrExit(uint64_t off, uint64_t len,
                            unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES]) {
    if (!enabled_) {
      std::cerr << "[gapbs] CXL sec: not enabled" << std::endl;
      std::exit(-129);
    }

    if (!use_mgr_) {
      std::memcpy(out_key, psk_key_, crypto_stream_chacha20_ietf_KEYBYTES);
      return;
    }

    EnsureAccessOrExit(off, len);
    const Entry* e = FindEntry(off, len);
    if (!e) {
      std::cerr << "[gapbs] CXL sec: no key entry for region off=" << off << " len=" << len << std::endl;
      std::exit(-130);
    }
    std::memcpy(out_key, e->key, crypto_stream_chacha20_ietf_KEYBYTES);
  }

  void GetVmKeyOrExit(unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES]) const {
    if (!enabled_ || use_mgr_) {
      std::cerr << "[gapbs] CXL sec: VM key is only available in crypto mode" << std::endl;
      std::exit(-131);
    }
    std::memcpy(out_key, psk_key_, crypto_stream_chacha20_ietf_KEYBYTES);
  }

  void GetCommonKeyOrExit(unsigned char out_key[crypto_stream_chacha20_ietf_KEYBYTES]) const {
    if (!enabled_ || use_mgr_) {
      std::cerr << "[gapbs] CXL sec: common key is only available in crypto mode" << std::endl;
      std::exit(-132);
    }
    if (has_common_key_) {
      std::memcpy(out_key, common_key_, crypto_stream_chacha20_ietf_KEYBYTES);
      return;
    }
    std::cerr << "[gapbs] CXL sec: missing CXL_SEC_COMMON_KEY_HEX" << std::endl;
    std::exit(-133);
  }

 private:
  Table* table() const {
    if (!base_) return nullptr;
    return reinterpret_cast<Table*>(base_ + kTableOffset);
  }

  bool enabled_;
  bool use_mgr_;
  bool has_common_key_;
  unsigned char psk_key_[crypto_stream_chacha20_ietf_KEYBYTES];
  unsigned char common_key_[crypto_stream_chacha20_ietf_KEYBYTES];
  unsigned char* base_;
  int fd_;
  unsigned node_id_;
  uint64_t principal_;
};

}  // namespace cxl_sec
}  // namespace gapbs

#else  // GAPBS_CXL_SECURE

namespace gapbs {
namespace cxl_sec {

inline bool EnvEnabled(const char*) { return false; }

}  // namespace cxl_sec
}  // namespace gapbs

#endif  // GAPBS_CXL_SECURE

#endif  // GAPBS_CXL_SEC_H_
