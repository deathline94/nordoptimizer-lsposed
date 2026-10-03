/*
 * Native junk-packet injection for NordLynx.
 *
 * Why this exists, in one measured line: the WireGuard handshake initiation does leave the phone
 *     192.168.0.179.49814 > 193.19.204.193.51820: UDP, length 148
 * and nothing ever answers it. AmneziaWG's countermeasure is to put unparseable datagrams in front of
 * that first packet *on the same socket*, so the flow the inspector sees does not begin with a
 * WireGuard initiation.
 *
 * Doing it from Java is impossible in this app, and four separate measurements said so: a hook on
 * java.net.DatagramSocket.send never fires while the tunnel is being established, /proc/net/udp and
 * /proc/self/fd are both unreadable from the app process, and the descriptors handed to
 * VpnService.protect(int) cannot be attributed to the tunnel. The socket belongs to libtelio.so.
 *
 * So the hook goes where the socket is: the sendto entry in the PLT of every library the app loaded
 * from its own install directory. Before the first sendto to the peer's port on a given descriptor,
 * Jc random-sized unparseable datagrams are written to that same descriptor, which is exactly the
 * AmneziaWG ordering -- same source port, same destination, garbage first.
 *
 * Kept deliberately small: no allocations on the send path, one bounded fd table, and the original
 * function pointer is used for both the junk and the real packet so nothing recurses.
 */

#include <jni.h>
#include <elf.h>
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "NOPT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define MAX_PATCHES 64
#define MAX_LIBS 96
#define MAX_JUNKED_FDS 32
#define MAX_JUNK_BYTES 1400

/* The PLT relocation entry type differs by word size, and reading a Rela as a Rel walks off the array. */
#ifdef __LP64__
typedef ElfW(Rela) RelEnt;
#define R_SYM(info) ELF64_R_SYM(info)
#define PLTREL_TYPE DT_RELA
#else
typedef ElfW(Rel) RelEnt;
#define R_SYM(info) ELF32_R_SYM(info)
#define PLTREL_TYPE DT_REL
#endif

static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

static struct {
    void **slot;
    void *original;
} patches[MAX_PATCHES];
static int patch_count;

static volatile int armed;
static volatile int dst_port = 51820;
static volatile int junk_count = 5;
static volatile int junk_min = 50;
static volatile int junk_max = 128;

/*
 * Per-descriptor burst bookkeeping. Junking only the first handshake attempt is not enough: the client
 * re-transmits its initiation roughly every 5s, so an inspector that samples a later packet still sees a
 * clean WireGuard handshake. AmneziaWG puts junk in front of each attempt, so a fresh burst is allowed once
 * the retransmit interval has passed.
 */
typedef struct {
    int fd;
    long long last_ms;
} JunkedFd;

static JunkedFd junked[MAX_JUNKED_FDS];
static volatile int junked_count;
static volatile long long bursts;

#define REJUNK_AFTER_MS 2000

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long) ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static unsigned int rng_state = 0x12345678u;

static unsigned int next_rand(void) {
    /* xorshift32: no libc call on the send path, which may be a signal-handling thread. */
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static int should_junk(int fd, long long now) {
    int n = junked_count;
    for (int i = 0; i < n; i++) {
        if (junked[i].fd != fd) continue;
        if (now - junked[i].last_ms < REJUNK_AFTER_MS) return 0;
        junked[i].last_ms = now;
        return 1;
    }
    if (n < MAX_JUNKED_FDS) {
        junked[n].fd = fd;
        junked[n].last_ms = now;
        junked_count = n + 1;
    }
    return 1;
}

static int port_of(const struct sockaddr *sa) {
    if (sa == NULL) return -1;
    if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *) sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
    return -1;
}

static void nap(void) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (8 + (long) (next_rand() % 18)) * 1000000L;
    nanosleep(&ts, NULL);
}

static void emit_junk(int fd, const struct sockaddr *to, socklen_t tolen) {
    int count = junk_count;
    int lo = junk_min;
    int hi = junk_max;
    if (count <= 0 || lo <= 0 || hi < lo) return;
    if (hi > MAX_JUNK_BYTES) hi = MAX_JUNK_BYTES;

    unsigned char buf[MAX_JUNK_BYTES];
    for (int i = 0; i < count; i++) {
        int span = hi - lo + 1;
        size_t n = (size_t) (lo + (span > 0 ? (int) (next_rand() % (unsigned) span) : 0));
        for (size_t k = 0; k < n; k++) buf[k] = (unsigned char) (next_rand() >> ((k & 3) * 8));
        if (real_sendto(fd, buf, n, 0, to, tolen) < 0) break;
        if (i + 1 < count) nap();
    }
    bursts++;
}

static ssize_t hook_sendto(int fd, const void *msg, size_t len, int flags, const struct sockaddr *to,
                           socklen_t tolen) {
    if (armed && to != NULL) {
        int p = port_of(to);
        int want = dst_port;
        if (p > 0 && p == want && should_junk(fd, now_ms())) {
            emit_junk(fd, to, tolen);
            LOGI("JUNK|native|fd=%d|to=%d|n=%d|sizes=%d-%d|bursts=%lld", fd, p, junk_count, junk_min,
                 junk_max, bursts);
        }
    }
    return real_sendto(fd, msg, len, flags, to, tolen);
}

static int protect_page(void *addr, size_t len) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    uintptr_t start = (uintptr_t) addr;
    uintptr_t aligned = start & ~(uintptr_t) (page - 1);
    return mprotect((void *) aligned, (start - aligned) + len, PROT_READ | PROT_WRITE);
}

/*
 * Patch the sendto PLT slot of one library, given its lowest mapped address. Android shared objects are
 * PIE, so the relocation offsets are relative to that base. The dynamic section is read in memory rather
 * than from the file, which avoids a second parse and works for whatever layout the linker produced.
 */
static int patch_library(uintptr_t base) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return 0;

    ElfW(Phdr) *phdr = (ElfW(Phdr) *) (base + ehdr->e_phoff);
    ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn) *) (base + phdr[i].p_vaddr);
            break;
        }
    }
    if (dyn == NULL) return 0;

    const char *strtab = NULL;
    ElfW(Sym) *symtab = NULL;
    void *jmprel = NULL;
    size_t pltrelrsz = 0;
    ElfW(Sxword) pltrel = 0;
    for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_STRTAB: strtab = (const char *) d->d_un.d_ptr; break;
            case DT_SYMTAB: symtab = (ElfW(Sym) *) d->d_un.d_ptr; break;
            case DT_JMPREL: jmprel = (void *) d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelrsz = (size_t) d->d_un.d_val; break;
            case DT_PLTREL: pltrel = d->d_un.d_val; break;
            default: break;
        }
    }
    if (strtab == NULL || symtab == NULL || jmprel == NULL || pltrelrsz == 0) return 0;
    /* Android's linker hands back file-relative addresses here; rebase what is clearly a relative value. */
    if ((uintptr_t) strtab < base) strtab = (const char *) (base + (uintptr_t) strtab);
    if ((uintptr_t) symtab < base) symtab = (ElfW(Sym) *) (base + (uintptr_t) symtab);
    if ((uintptr_t) jmprel < base) jmprel = (void *) (base + (uintptr_t) jmprel);

    int patched = 0;
    if (pltrel != PLTREL_TYPE) return 0;
    RelEnt *rel = (RelEnt *) jmprel;
    size_t entsz = sizeof(RelEnt);
    for (size_t off = 0; off + entsz <= pltrelrsz; off += entsz) {
        RelEnt *entry = (RelEnt *) ((char *) rel + off);
        uint32_t sym_index = R_SYM(entry->r_info);
        const char *name = strtab + symtab[sym_index].st_name;
        if (strcmp(name, "sendto") != 0) continue;

        uintptr_t slot_addr = entry->r_offset;
        if (slot_addr < base) slot_addr += base;
        void **slot = (void **) slot_addr;
        if (patch_count >= MAX_PATCHES) return patched;
        if (*slot == (void *) hook_sendto) { patched++; continue; }

        if (protect_page(slot, sizeof(void *)) != 0) continue;
        patches[patch_count].slot = slot;
        patches[patch_count].original = *slot;
        patch_count++;
        *slot = (void *) hook_sendto;
        patched++;
    }
    return patched;
}

static int hook_all_app_libraries(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) return -1;

    char line[1024];
    uintptr_t lowest[MAX_LIBS];
    char names[MAX_LIBS][192];
    int count = 0;
    int total = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        unsigned long offset = 0;
        int path_at = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %n", &start, &end, perms, &offset, &path_at) < 4) continue;
        const char *path = line + path_at;
        while (*path == ' ') path++;
        size_t plen = strlen(path);
        while (plen > 0 && (path[plen - 1] == '\n' || path[plen - 1] == '\r' || path[plen - 1] == ' ')) {
            ((char *) path)[plen - 1] = '\0';
            plen--;
        }
        if (plen < 4 || strstr(path, ".so") == NULL) continue;
        if (strncmp(path, "/data/app/", 10) != 0 && strncmp(path, "/data/adb/", 10) != 0) continue;
        if (offset != 0) continue;                       /* only the first mapping is the ELF base */
        if (perms[0] != 'r') continue;

        int known = 0;
        for (int i = 0; i < count; i++) {
            if (strcmp(names[i], path) == 0) { known = 1; break; }
        }
        if (known || count >= MAX_LIBS) continue;
        snprintf(names[count], sizeof(names[count]), "%s", path);
        lowest[count] = (uintptr_t) start;
        count++;
    }
    fclose(f);

    for (int i = 0; i < count; i++) {
        int n = patch_library(lowest[i]);
        if (n > 0) {
            total += n;
            LOGI("JUNK|plt|%s|slots=%d", names[i], n);
        }
    }
    return total;
}

JNIEXPORT jint JNICALL
Java_com_nordoptimizer_lsposed_hooks_JunkPacketSender_nativeArm(JNIEnv *env, jclass cls, jint port,
                                                               jint count, jint min, jint max) {
    (void) env;
    (void) cls;
    if (real_sendto == NULL) {
        void *sym = dlsym(RTLD_DEFAULT, "sendto");
        if (sym == NULL) {
            LOGE("JUNK|native|sendto-not-found");
            return -1;
        }
        real_sendto = (ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t)) sym;
    }
    dst_port = port > 0 ? port : 51820;
    junk_count = count > 0 && count <= 20 ? count : 5;
    junk_min = min > 0 ? min : 50;
    junk_max = max >= junk_min ? max : junk_min + 78;
    junked_count = 0;
    int slots = hook_all_app_libraries();
    armed = 1;
    rng_state ^= (unsigned) time(NULL) + 0x9e3779b9u;
    LOGI("JUNK|arm|port=%d|n=%d|sizes=%d-%d|slots=%d", dst_port, junk_count, junk_min, junk_max, slots);
    return slots;
}

JNIEXPORT jlong JNICALL
Java_com_nordoptimizer_lsposed_hooks_JunkPacketSender_nativeBursts(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
    return (jlong) bursts;
}

JNIEXPORT jint JNICALL
Java_com_nordoptimizer_lsposed_hooks_JunkPacketSender_nativeDisarm(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
    armed = 0;
    for (int i = 0; i < patch_count; i++) {
        if (patches[i].slot != NULL && patches[i].original != NULL) {
            if (protect_page((void *) patches[i].slot, sizeof(void *)) == 0) {
                *patches[i].slot = patches[i].original;
            }
        }
    }
    patch_count = 0;
    return 0;
}
