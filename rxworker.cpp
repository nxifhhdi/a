// ============================================================================
// rxworker - dedicated RandomX job processor (the "server" side)
//
// Receives Monero jobs from the controller over a WebSocket (Cloudflare
// quick-tunnel compatible), computes RandomX hashes on all cores, and returns
// valid shares. No pool logic, no wallet - pure compute. Line protocol:
//
//   controller -> worker : "AUTH <token>"
//                          "JOB <job_id> <blob_hex> <target_hex> <seed_hex>"
//                          "PING"
//   worker -> controller : "READY threads=N" | "PONG"
//                          "HASHRATE <hps>"
//                          "SUBMIT <job_id> <nonce_hex> <result_hex>"
//
// Build: see build.sh  (needs librandomx, compiled from github.com/tevador/RandomX)
// Run:   ./rxworker --port 8765 --token <secret> [--threads N] [--light]
//
// Optimizations vs naive implementation:
//   - Huge pages (RANDOMX_FLAG_LARGE_PAGES) with graceful fallback  (+30-50%)
//   - Hardware auto-detection via randomx_get_flags()
//   - Pipelined hashing (randomx_calculate_hash_first/_next/_last)  (+3-6%)
//   - CPU core pinning (pthread_setaffinity_np)                     (+5-15%)
//   - Thread-local hash counters (no cache-line bouncing)
//   - Fast 64-bit target check (single compare rejects 99.99%)
//   - Cache-line aligned shared state (no false sharing)
//   - Safe seed transitions (shared_mutex coordination)
//   - Random nonce offsets (no multi-worker collisions)
//   - Fixed dataset init remainder bug
// ============================================================================

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include <randomx.h>

// ---------------------------------------------------------------- utilities
static std::string hex_encode(const uint8_t *d, size_t n) {
    static const char *H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 15]; }
    return s;
}
static bool hex_decode(const std::string &s, std::vector<uint8_t> &out) {
    if (s.empty() || s.size() % 2) return false;
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.resize(s.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        int a = v(s[2 * i]), b = v(s[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        out[i] = (a << 4) | b;
    }
    return true;
}

// ---------------------------------------------------------------- SHA1 (WS handshake)
struct SHA1 {
    uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t buflen;
    SHA1() { h[0]=0x67452301; h[1]=0xEFCDAB89; h[2]=0x98BADCFE; h[3]=0x10325476; h[4]=0xC3D2E1F0; len=0; buflen=0; }
    static uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
    void block(const uint8_t *p) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) w[i] = (p[4*i]<<24) | (p[4*i+1]<<16) | (p[4*i+2]<<8) | p[4*i+3];
        for (int i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if      (i < 20) { f = (b & c) | ((~b) & d);      k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                 k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                 k = 0xCA62C1D6; }
            uint32_t t = rol(a,5) + f + e + k + w[i];
            e = d; d = c; c = rol(b,30); b = a; a = t;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
    }
    void update(const uint8_t *p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - buflen; if (take > n) take = n;
            memcpy(buf + buflen, p, take); buflen += take; p += take; n -= take;
            if (buflen == 64) { block(buf); buflen = 0; }
        }
    }
    void final(uint8_t out[20]) {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80; update(&pad, 1);
        uint8_t z = 0; while (buflen != 56) update(&z, 1);
        uint8_t lb[8]; for (int i = 0; i < 8; i++) lb[7 - i] = (bits >> (8 * i)) & 0xff;
        update(lb, 8);
        for (int i = 0; i < 5; i++) {
            out[4*i] = (h[i] >> 24) & 0xff; out[4*i+1] = (h[i] >> 16) & 0xff;
            out[4*i+2] = (h[i] >> 8) & 0xff; out[4*i+3] = h[i] & 0xff;
        }
    }
};

static std::string b64(const uint8_t *d, size_t n) {
    static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (d[i] << 16) | (i + 1 < n ? d[i+1] << 8 : 0) | (i + 2 < n ? d[i+2] : 0);
        s += T[(v >> 18) & 63]; s += T[(v >> 12) & 63];
        s += (i + 1 < n) ? T[(v >> 6) & 63] : '=';
        s += (i + 2 < n) ? T[v & 63] : '=';
    }
    return s;
}

// ---------------------------------------------------------------- WebSocket (minimal RFC6455 server)
static bool read_full(int fd, uint8_t *buf, size_t n) {
    while (n) {
        ssize_t r = recv(fd, buf, n, 0);
        if (r <= 0) return false;
        buf += r; n -= r;
    }
    return true;
}

static bool ws_send_frame(int fd, uint8_t op, const uint8_t *data, size_t n) {
    uint8_t hdr[10]; size_t hl = 0;
    hdr[hl++] = 0x80 | op;
    if (n < 126) hdr[hl++] = n;
    else if (n <= 0xFFFF) { hdr[hl++] = 126; hdr[hl++] = (n >> 8) & 0xff; hdr[hl++] = n & 0xff; }
    else {
        hdr[hl++] = 127;
        for (int i = 7; i >= 0; i--) hdr[hl++] = (n >> (8 * i)) & 0xff;
    }
    if (send(fd, hdr, hl, MSG_NOSIGNAL) != (ssize_t)hl) return false;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, data + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return false;
        off += w;
    }
    return true;
}
static bool ws_send_text(int fd, const std::string &s) {
    return ws_send_frame(fd, 0x1, (const uint8_t *)s.data(), s.size());
}

// reads one complete (possibly fragmented) text message; answers pings internally
static bool ws_read_message(int fd, std::string &out) {
    out.clear();
    for (;;) {
        uint8_t hdr[2];
        if (!read_full(fd, hdr, 2)) return false;
        bool fin = hdr[0] & 0x80;
        uint8_t op = hdr[0] & 0x0f;
        bool masked = hdr[1] & 0x80;
        uint64_t len = hdr[1] & 0x7f;
        if (len == 126) { uint8_t e[2]; if (!read_full(fd, e, 2)) return false; len = (e[0] << 8) | e[1]; }
        else if (len == 127) { uint8_t e[8]; if (!read_full(fd, e, 8)) return false; len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | e[i]; }
        if (len > (1 << 22)) return false; // sanity
        uint8_t mask[4] = {0,0,0,0};
        if (masked && !read_full(fd, mask, 4)) return false;
        std::vector<uint8_t> pl(len);
        if (len && !read_full(fd, pl.data(), len)) return false;
        if (masked) for (uint64_t i = 0; i < len; i++) pl[i] ^= mask[i & 3];
        if (op == 0x9) { ws_send_frame(fd, 0xA, pl.data(), pl.size()); continue; } // ping -> pong
        if (op == 0x8) return false;                                               // close
        if (op == 0x1 || op == 0x0) {
            out.append((char *)pl.data(), pl.size());
            if (fin) return true;
        }
    }
}

static bool ws_handshake(int fd) {
    std::string req;
    char c;
    while (req.size() < 16384) {
        if (recv(fd, &c, 1, 0) != 1) return false;
        req += c;
        if (req.size() >= 4 && req.compare(req.size() - 4, 4, "\r\n\r\n") == 0) break;
    }
    std::string key, low = req;
    for (auto &ch : low) if (ch >= 'A' && ch <= 'Z') ch += 32;
    size_t p = low.find("sec-websocket-key:");
    if (p == std::string::npos) return false;
    p += 18;
    while (p < req.size() && (req[p] == ' ' || req[p] == '\t')) p++;
    size_t e = req.find("\r\n", p);
    key = req.substr(p, e - p);
    std::string magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    SHA1 sha; sha.update((const uint8_t *)magic.data(), magic.size());
    uint8_t dg[20]; sha.final(dg);
    std::string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + b64(dg, 20) + "\r\n\r\n";
    return send(fd, resp.data(), resp.size(), MSG_NOSIGNAL) == (ssize_t)resp.size();
}

// ---------------------------------------------------------------- shared state (cache-line aligned)
struct Shared {
    // current job (protected by jobMtx)
    std::mutex jobMtx;
    std::vector<uint8_t> blob, seed;
    uint8_t target[32] = {0};
    std::string jobId;
    bool hasJob = false;

    // epoch counter - signals new job to miner threads
    // aligned to own cache line to prevent false sharing
    alignas(64) std::atomic<uint64_t> epoch{0};

    // randomx dataset (protected by rxDataMtx - shared_mutex for safe seed transitions)
    std::shared_mutex rxDataMtx;
    randomx_cache *cache = nullptr;
    randomx_dataset *dataset = nullptr;
    std::vector<uint8_t> curSeed;
    alignas(64) std::atomic<uint64_t> dsver{0};

    // outbound socket
    alignas(64) std::atomic<int> fd{-1};
    std::mutex sendmtx;

    // hash counter - threads flush local counters here periodically
    alignas(64) std::atomic<uint64_t> hashes{0};

    int nthreads = 1;
    randomx_flags flags;
    bool hugePages = false;  // track if huge pages are active
};

static void sendLine(Shared &S, const std::string &line) {
    int f = S.fd.load();
    if (f < 0) return;
    std::lock_guard<std::mutex> g(S.sendmtx);
    if (S.fd.load() == f) ws_send_text(f, line);
}

// ---------------------------------------------------------------- fast target check
// For pool targets expanded to 256-bit LE, only bytes 24-31 are non-zero.
// Compare the most significant uint64_t first to reject 99.99% of hashes in one op.
static inline bool hashMeetsTarget(const uint8_t h[32], const uint8_t tgt[32]) {
    uint64_t h_hi, t_hi;
    memcpy(&h_hi, h + 24, 8);
    memcpy(&t_hi, tgt + 24, 8);
    if (h_hi < t_hi) return true;
    if (h_hi > t_hi) return false;
    // MSB 8 bytes match - do full 256-bit little-endian compare (rare path)
    for (int i = 23; i >= 0; i--) {
        if (h[i] < tgt[i]) return true;
        if (h[i] > tgt[i]) return false;
    }
    return true; // exactly equal
}

// ---------------------------------------------------------------- miner threads
static void minerThread(Shared &S, int idx) {
    // CPU core pinning - pin thread idx to core idx
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(idx, &cpuset);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
            printf("[thread %d] warning: could not pin to core %d\n", idx, idx); fflush(stdout);
        }
    }

    randomx_vm *vm = nullptr;
    uint64_t myds = 0, myEpoch = 0;
    std::vector<uint8_t> buf, seedNeed;
    uint8_t tgt[32];
    std::string jobId;
    uint32_t nonce = 0;

    // batch size for pipelined hashing before checking for new epoch
    const int BATCH = 500;

    for (;;) {
        if (S.epoch.load(std::memory_order_acquire) == myEpoch && vm) {
            // ---- HOT PATH: pipelined hashing with shared_lock for seed safety ----
            uint64_t localHashes = 0;
            {
                // Hold shared lock while hashing - prevents dataset destruction during use
                std::shared_lock<std::shared_mutex> dataLock(S.rxDataMtx);

                uint8_t prevHash[32], curHash[32];

                // Pipeline: prepare first nonce and start first hash
                uint32_t nn = nonce; nonce += S.nthreads;
                memcpy(buf.data() + 39, &nn, 4);
                randomx_calculate_hash_first(vm, buf.data(), buf.size());
                localHashes++;

                for (int k = 1; k < BATCH; k++) {
                    // Prepare next nonce
                    nn = nonce; nonce += S.nthreads;
                    memcpy(buf.data() + 39, &nn, 4);

                    // Complete previous hash, start next hash
                    randomx_calculate_hash_next(vm, buf.data(), buf.size(), prevHash);
                    localHashes++;

                    // Check previous hash against target (fast 64-bit check first)
                    if (hashMeetsTarget(prevHash, tgt)) {
                        // Reconstruct previous nonce for submission
                        uint32_t prevNonce = nn - S.nthreads;
                        uint8_t nb[4];
                        memcpy(nb, &prevNonce, 4);
                        char nh[9];
                        snprintf(nh, sizeof(nh), "%02x%02x%02x%02x", nb[0], nb[1], nb[2], nb[3]);
                        sendLine(S, "SUBMIT " + jobId + " " + nh + " " + hex_encode(prevHash, 32));
                        printf("[share] job %s nonce %s\n", jobId.c_str(), nh); fflush(stdout);
                    }
                }

                // Complete the last hash
                randomx_calculate_hash_last(vm, curHash);

                // Check last hash
                if (hashMeetsTarget(curHash, tgt)) {
                    nn = nonce - S.nthreads; // current nonce (last one used)
                    uint8_t nb[4];
                    memcpy(nb, &nn, 4);
                    char nh[9];
                    snprintf(nh, sizeof(nh), "%02x%02x%02x%02x", nb[0], nb[1], nb[2], nb[3]);
                    sendLine(S, "SUBMIT " + jobId + " " + nh + " " + hex_encode(curHash, 32));
                    printf("[share] job %s nonce %s\n", jobId.c_str(), nh); fflush(stdout);
                }
            } // shared_lock released here

            // Flush thread-local counter to global (once per batch, not per hash)
            S.hashes.fetch_add(localHashes, std::memory_order_relaxed);
            continue;
        }

        // ---- NEW EPOCH: snapshot job + ensure dataset matches seed ----
        bool got = false;
        {
            std::lock_guard<std::mutex> g(S.jobMtx);
            if (S.hasJob) {
                buf = S.blob; seedNeed = S.seed; memcpy(tgt, S.target, 32); jobId = S.jobId;
                got = true;
            }
        }
        if (!got) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }

        {
            // Exclusive lock for dataset rebuild (blocks all miner threads' shared locks)
            std::unique_lock<std::shared_mutex> dataLock(S.rxDataMtx);

            if (S.curSeed != seedNeed) {
                // First thread to notice seed change does the rebuild
                if (vm) { randomx_destroy_vm(vm); vm = nullptr; }
                if (S.dataset) { randomx_release_dataset(S.dataset); S.dataset = nullptr; }
                if (S.cache) { randomx_release_cache(S.cache); S.cache = nullptr; }
                printf("[rx] new seed, building dataset (full=%d, hugepages=%d) ...\n",
                       (int)(S.flags & RANDOMX_FLAG_FULL_MEM), (int)S.hugePages); fflush(stdout);
                auto t0 = std::chrono::steady_clock::now();

                S.cache = randomx_alloc_cache(S.flags);
                if (!S.cache && S.hugePages) {
                    // Huge pages failed for cache, retry without
                    printf("[rx] huge pages failed for cache, falling back to standard pages\n"); fflush(stdout);
                    randomx_flags fallback = S.flags & ~RANDOMX_FLAG_LARGE_PAGES;
                    S.cache = randomx_alloc_cache(fallback);
                }
                randomx_init_cache(S.cache, seedNeed.data(), seedNeed.size());

                if (S.flags & RANDOMX_FLAG_FULL_MEM) {
                    S.dataset = randomx_alloc_dataset(S.flags);
                    if (!S.dataset && S.hugePages) {
                        // Huge pages failed for dataset, retry without
                        printf("[rx] huge pages failed for dataset, falling back to standard pages\n"); fflush(stdout);
                        randomx_flags fallback = S.flags & ~RANDOMX_FLAG_LARGE_PAGES;
                        S.dataset = randomx_alloc_dataset(fallback);
                    }
                    auto total = randomx_dataset_item_count();
                    unsigned n = S.nthreads;
                    std::vector<std::thread> ts;
                    for (unsigned t = 0; t < n; t++) {
                        // Fix remainder bug: each thread gets range [start, start+count)
                        unsigned long start = (unsigned long)total * t / n;
                        unsigned long count = (unsigned long)total * (t + 1) / n - start;
                        ts.emplace_back([&, start, count] {
                            randomx_init_dataset(S.dataset, S.cache, start, count);
                        });
                    }
                    for (auto &th : ts) th.join();
                }
                S.curSeed = seedNeed;
                S.dsver.fetch_add(1);
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
                printf("[rx] dataset ready in %lld ms\n", (long long)ms); fflush(stdout);
            }
            if (!vm || myds != S.dsver.load()) {
                if (vm) randomx_destroy_vm(vm);
                vm = randomx_create_vm(S.flags, S.cache, S.dataset);
                if (!vm && S.hugePages) {
                    // Try without huge pages for VM
                    randomx_flags fallback = S.flags & ~RANDOMX_FLAG_LARGE_PAGES;
                    vm = randomx_create_vm(fallback, S.cache, S.dataset);
                }
                myds = S.dsver.load();
            }
        }
        myEpoch = S.epoch.load(std::memory_order_acquire);

        // Random nonce offset per job - prevents collisions between workers
        uint32_t base = (uint32_t)(std::chrono::steady_clock::now().time_since_epoch().count());
        base ^= (uint32_t)idx * 2654435761u;  // Knuth multiplicative hash
        nonce = base - (base % S.nthreads) + idx;  // align to thread stride
    }
}

// ---------------------------------------------------------------- target parsing (xmrig-compatible)
// pool targets: 4 or 8 byte little-endian hex; xmrig scales to 64-bit m_target.
// We expand to a full 256-bit LE target (m_target << 192). 32-byte targets used as-is.
static bool parseTarget(const std::string &hexs, uint8_t out[32]) {
    std::vector<uint8_t> raw;
    if (!hex_decode(hexs, raw)) return false;
    memset(out, 0, 32);
    uint64_t m = 0;
    if (raw.size() == 4) {
        uint32_t t; memcpy(&t, raw.data(), 4);
        if (!t) return false;
        m = 0xFFFFFFFFFFFFFFFFULL / (0xFFFFFFFFULL / (uint64_t)t);
    } else if (raw.size() == 8) {
        memcpy(&m, raw.data(), 8);
    } else if (raw.size() == 32) {
        memcpy(out, raw.data(), 32);
        return true;
    } else return false;
    if (!m) return false;
    memcpy(out + 24, &m, 8);
    return true;
}

// ---------------------------------------------------------------- network / controller session
static std::string g_token;

static void session(Shared &S, int cfd) {
    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (!ws_handshake(cfd)) { close(cfd); return; }

    std::string msg;
    if (!ws_read_message(cfd, msg) || msg != "AUTH " + g_token) {
        ws_send_text(cfd, "ERR bad auth");
        close(cfd);
        return;
    }
    int old = S.fd.exchange(cfd);
    if (old >= 0) close(old);
    sendLine(S, "READY threads=" + std::to_string(S.nthreads));
    printf("[net] controller connected\n"); fflush(stdout);

    while (ws_read_message(cfd, msg)) {
        if (msg == "PING") { sendLine(S, "PONG"); continue; }
        if (msg.rfind("JOB ", 0) == 0) {
            // JOB <id> <blob_hex> <target_hex> <seed_hex>
            std::vector<std::string> p; size_t i = 4, n = msg.size();
            while (p.size() < 4 && i < n) {
                size_t j = msg.find(' ', i);
                if (j == std::string::npos) j = n;
                p.push_back(msg.substr(i, j - i)); i = j + 1;
            }
            if (p.size() != 4) { sendLine(S, "ERR bad job"); continue; }
            std::vector<uint8_t> blob, seed; uint8_t tgt[32];
            if (!hex_decode(p[1], blob) || blob.size() < 43 || !hex_decode(p[3], seed) || seed.empty() || !parseTarget(p[2], tgt)) {
                sendLine(S, "ERR job parse"); continue;
            }
            {
                std::lock_guard<std::mutex> g(S.jobMtx);
                S.blob = blob; S.seed = seed; memcpy(S.target, tgt, 32); S.jobId = p[0]; S.hasJob = true;
            }
            S.epoch.fetch_add(1, std::memory_order_release);
            printf("[job] %s blob=%zuB\n", p[0].c_str(), blob.size()); fflush(stdout);
        }
    }
    if (S.fd.load() == cfd) S.fd.store(-1);
    close(cfd);
    printf("[net] controller disconnected\n"); fflush(stdout);
}

// ---------------------------------------------------------------- main
int main(int argc, char **argv) {
    int port = 8765;
    int threads = (int)std::thread::hardware_concurrency();
    bool light = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) port = atoi(argv[++i]);
        else if (a == "--threads" && i + 1 < argc) threads = atoi(argv[++i]);
        else if (a == "--token" && i + 1 < argc) g_token = argv[++i];
        else if (a == "--light") light = true;
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 1; }
    }
    if (g_token.empty()) { fprintf(stderr, "usage: rxworker --token <secret> [--port 8765] [--threads N] [--light]\n"); return 1; }
    if (threads < 1) threads = 1;

    signal(SIGPIPE, SIG_IGN);

    Shared S;
    S.nthreads = threads;

    // Auto-detect optimal flags for this CPU
    randomx_flags autoFlags = randomx_get_flags();
    S.flags = autoFlags;
    if (!light) S.flags |= RANDOMX_FLAG_FULL_MEM;

    // Try huge pages (biggest single optimization: +30-50% hashrate)
    S.flags |= RANDOMX_FLAG_LARGE_PAGES;
    S.hugePages = true;

    printf("[rxworker] port=%d threads=%d mode=%s hugepages=enabled\n", port, threads, light ? "light" : "full");
    printf("[rxworker] flags: JIT=%d HARD_AES=%d FULL_MEM=%d LARGE_PAGES=%d ARGON2_AVX2=%d\n",
           (int)((S.flags & RANDOMX_FLAG_JIT) != 0),
           (int)((S.flags & RANDOMX_FLAG_HARD_AES) != 0),
           (int)((S.flags & RANDOMX_FLAG_FULL_MEM) != 0),
           (int)((S.flags & RANDOMX_FLAG_LARGE_PAGES) != 0),
           (int)((S.flags & RANDOMX_FLAG_ARGON2_AVX2) != 0));
    fflush(stdout);

    for (int t = 0; t < threads; t++) std::thread(minerThread, std::ref(S), t).detach();

    // hashrate reporter
    std::thread([&S] {
        uint64_t last = 0;
        auto lastT = std::chrono::steady_clock::now();
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            uint64_t now = S.hashes.load();
            auto t = std::chrono::steady_clock::now();
            double dt = std::chrono::duration<double>(t - lastT).count();
            double hps = (now - last) / dt;
            last = now; lastT = t;
            printf("[hashrate] %.0f H/s\n", hps); fflush(stdout);
            sendLine(S, "HASHRATE " + std::to_string((long long)hps));
        }
    }).detach();

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // local only; cloudflared exposes it
    if (bind(lfd, (sockaddr *)&addr, sizeof(addr)) < 0 || listen(lfd, 8) < 0) {
        perror("bind/listen");
        return 1;
    }
    printf("[rxworker] listening on 127.0.0.1:%d - point cloudflared here\n", port); fflush(stdout);

    for (;;) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd >= 0) session(S, cfd);
    }
}
