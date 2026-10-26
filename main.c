#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <pongo.h>

#define AES_ENCRYPT     0x00000000
#define AES_CBC         0x00000000
#define AES_128         0x10000000
#define AES_256         0x30000000

#define AES_USER_KEY    0x00000000
#define AES_UID         0x00000001

#define NONCE_SEED_SLOT_UPDATE_REQUIRED  (1u << 0)
#define NONCE_SEED_SLOT_ROLLED           (1u << 1)
#define NONCE_SEED_SLOT_PROPOSED         (1u << 2)
#define NONCE_SEED_SLOT_AP_SHADOWED      (1u << 3)
#define NONCE_SEED_SLOT_LEGACY_MIGRATION (1u << 4)
#define NONCE_SEED_SLOT_LEGACY_PRESERVE  (1u << 5)
#define NONCE_SEED_SLOT_ENTANGLE_8A4     (1u << 6)

#define NONCE_SEED_ROLLED           (1u << 0)
#define NONCE_SEED_PROPOSED         (1u << 1)
#define NONCE_SEED_AP_SHADOWED      (1u << 3)

#pragma pack(push, 8)
typedef struct {
    uint16_t version;
    uint64_t size;
    uint8_t data[48];
} bnch_slot_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct  __attribute__((packed)) {
    uint8_t version;
    uint32_t flags_be;
    uint8_t data[16];
    uint8_t proposed_data[16];
} nonce_seed_slot_t;
struct __attribute__((packed)) nonce_seed {
    uint64_t flags;
    uint8_t data[16];
    uint8_t proposed_data[16];
};
typedef struct __attribute__((packed)) {
    uint8_t undefined; // idk
    uint64_t count;
} nonce_domain_t;
typedef struct __attribute__((packed)) {
    uint16_t version;
    bnch_slot_t bnch;
    nonce_domain_t domain;
    struct nonce_seed seed[];
} nonce_seed_hdr_t;
#pragma pack(pop)

extern int aes(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key);

static const uint8_t derived_key_8a3[0x10] = {
    0x56, 0x82, 0x41, 0x65, 0x65, 0x51, 0xe0, 0xcd,
    0xf5, 0x6f, 0xf8, 0x4c, 0xc1, 0x1a, 0x79, 0xef
};
static const uint8_t derived_key_8a4[0x10] = {
    0x0c, 0x31, 0xf7, 0xdf, 0x81, 0x92, 0x4d, 0x03,
    0x8c, 0xb4, 0x37, 0xfa, 0x03, 0x60, 0xf7, 0xc9
};

static bool decode_nvram_proxy_data(const uint8_t* data, const size_t len, void** outbuf, size_t* outlen)
{
    if ((!data && len) || !outbuf || !outlen) {
        return false;
    }
    
    size_t maxcnt = 0;
    for (size_t i = 0; i < len; i++) {
        size_t count = 1;
        if (data[i] == 0xff) {
            if (++i >= len) {
                return false;
            }
            count = data[i] & 0x7f;
        }
        if (count > SIZE_MAX - maxcnt) {
            return false;
        }
        maxcnt += count;
    }
    uint8_t* b = malloc(maxcnt ? maxcnt : 1);
    if (!b) {
        return false;
    }
    size_t cnt = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == 0xff) {
            i++;
            size_t count = data[i] & 0x7f;
            memset(b + cnt, (data[i] & 0x80) ? 0xff : 0x00, count);
            cnt += count;
        }
        else {
            b[cnt++] = data[i];
        }
    }
    if (maxcnt != cnt) {
        free(b);
        return false;
    }
    *outbuf = b;
    *outlen = cnt;
    return true;
}

static void show_aes_key_internal(uint32_t key_id, const uint8_t* derived_key)
{
    static const size_t _keylen = 0x10;
    static const uint8_t zero_iv[0x10] = { 0 };
    uint8_t* _key = alloc_contig(_keylen);
    if (!_key) {
        iprintf("aes: malloc failed (%lu)\n", _keylen);
        return;
    }
    memcpy(_key, derived_key, _keylen);
    
    int rv = aes(AES_ENCRYPT | AES_CBC | AES_256 | AES_UID, _key, _key, _keylen, zero_iv, NULL);
    if (rv) {
        iprintf("aes failed: %d\n", rv);
        free_contig(_key, _keylen);
        return;
    }
    
    iprintf("key 0x%x: 0x", key_id);
    for (int i = 0; i < _keylen; i++) {
        iprintf("%02x", _key[i]);
    }
    iprintf("\n");
    free_contig(_key, _keylen);
}

static void show_aes_key_8a3(void)
{
    show_aes_key_internal(0x8a3, derived_key_8a3);
}

static void show_aes_key_8a4(void)
{
    show_aes_key_internal(0x8a4, derived_key_8a4);
}

static void show_current_c1bt(void)
{
    dt_node_t* chosen = dt_find(gDeviceTree, "chosen");
    if (!chosen) {
        iprintf("dt_find: failed (no device)\n");
        return;
    }
    
    size_t nvram_proxy_data_len = 0;
    void* nvram_proxy_data = dt_prop(chosen, "nvram-proxy-data", &nvram_proxy_data_len);
    if (!nvram_proxy_data) {
        iprintf("dt_prop: failed (no nvram-proxy-data prop)\n");
        return;
    }
    
    const char* str = "krn.c1bt=";
    size_t str_length = 9;
    uint8_t* cur = memmem(nvram_proxy_data, nvram_proxy_data_len, str, str_length);
    if (!cur) {
        iprintf("memmem: failed (no krn.c1bt value)\n");
        // try nonce-seeds
        const char* alt_str = "nonce-seeds=";
        str_length = 12;
        cur = memmem(nvram_proxy_data, nvram_proxy_data_len, alt_str, str_length);
        if (!cur) {
            iprintf("memmem: failed (no nonce-seeds value)\n");
            return;
        }
    }
    
    cur += str_length;
    size_t remaining = nvram_proxy_data_len - (size_t)(cur - (uint8_t *)nvram_proxy_data);
    uint8_t *terminator = memchr(cur, 0, remaining);
    if (!terminator) {
        iprintf("nvram-proxy-data: unterminated value\n");
        return;
    }
    size_t cnt = (size_t)(terminator - cur);
    
    uint8_t* value = NULL;
    size_t value_length = 0;
    bool rv = decode_nvram_proxy_data(cur, cnt, (void*)&value, &value_length);
    if (rv != true) {
        iprintf("decode_nvram_proxy_data: failed\n");
        return;
    }
    if (!value || !value_length) {
        iprintf("no buffer!?\n");
        goto end;
    }
    
    if (str_length == 9) {
        if (value_length != sizeof(nonce_seed_slot_t)) {
            iprintf("nonce_seed_slot: unknown struct length\n");
            goto end;
        }
        nonce_seed_slot_t* slot = (nonce_seed_slot_t*)value;
        uint32_t flags = __builtin_bswap32(slot->flags_be);
        if (slot->version != 0) {
            iprintf("nonce_seed_slot: unknown version\n");
            goto end;
        }
        
        if (flags & NONCE_SEED_SLOT_UPDATE_REQUIRED) {
            iprintf("nonce_seed_slot: krn.c1bt requires a seed update\n");
        }
        if (flags & NONCE_SEED_SLOT_ROLLED) {
            iprintf("nonce_seed_slot: krn.c1bt is rolled\n");
        }
        if (flags & NONCE_SEED_SLOT_PROPOSED) {
            iprintf("nonce_seed_slot: krn.c1bt has a proposed seed\n");
        }
        if (flags & NONCE_SEED_SLOT_AP_SHADOWED) {
            iprintf("nonce_seed_slot: krn.c1bt is an AP shadow domain\n");
        }
        if (flags & NONCE_SEED_SLOT_LEGACY_MIGRATION) {
            iprintf("nonce_seed_slot: krn.c1bt has legacy migration state\n");
        }
        if (flags & NONCE_SEED_SLOT_LEGACY_PRESERVE) {
            iprintf("nonce_seed_slot: krn.c1bt has the legacy seed-preservation flag\n");
        }
        if (flags & NONCE_SEED_SLOT_ENTANGLE_8A4) {
            iprintf("nonce_seed_slot: krn.c1bt requires AES entanglement with key 0x8a4\n");
        }
        
        if (flags & (NONCE_SEED_SLOT_UPDATE_REQUIRED | NONCE_SEED_SLOT_ROLLED | NONCE_SEED_SLOT_PROPOSED)) {
            goto end;
        }
        
        iprintf("krn.c1bt seed: 0x");
        for (int i = 0; i < 0x10; i++) {
            iprintf("%02x", slot->data[i]);
        }
        iprintf("\n");
    }
    
    if (str_length == 12) {
        int idx = 7;
        const size_t header_size = offsetof(nonce_seed_hdr_t, seed);
        if (value_length < header_size) {
            iprintf("nonce-seeds: truncated header\n");
            goto end;
        }
        nonce_seed_hdr_t* hdr = (nonce_seed_hdr_t*)value;
        if (hdr->version != 2) {
            iprintf("nonce-seeds: unknown nonce_seeds version\n");
            goto end;
        }
        if (hdr->domain.count > (value_length - header_size) / sizeof(hdr->seed[0])) {
            iprintf("nonce-seeds: truncated seed array\n");
            goto end;
        }
        if (hdr->bnch.version != 0) {
            iprintf("nonce-seeds: unknown bnch_slot version\n");
            goto end;
        }
        if (hdr->domain.undefined != 1) {
            iprintf("nonce-seeds: unknown nonce_domain format\n");
            goto end;
        }
        if (hdr->domain.count <= idx) {
            iprintf("nonce-seeds: nonce_domain(%d) not found\n", idx);
            goto end;
        }
        if ((hdr->seed[idx].flags & (NONCE_SEED_ROLLED | NONCE_SEED_PROPOSED)) != 0) {
            if (hdr->seed[idx].flags & NONCE_SEED_ROLLED) {
                iprintf("nonce-seeds: nonce_domain(%d) is rolled\n", idx);
            }
            if (hdr->seed[idx].flags & NONCE_SEED_PROPOSED) {
                iprintf("nonce-seeds: nonce_domain(%d) has a proposed seed\n", idx);
            }
            goto end;
        }
        if (hdr->seed[idx].flags & NONCE_SEED_AP_SHADOWED) {
            iprintf("nonce-seeds: nonce_domain(%d) is an AP shadow domain\n", idx);
        }
        
        iprintf("nonce_domain(%d): 0x", idx);
        for (int i = 0; i < 0x10; i++) {
            iprintf("%02x", hdr->seed[idx].data[i]);
        }
        iprintf("\n");
    }
end:
    if (value) {
        free(value);
    }
}

void module_entry(void)
{
    puts("");
    puts("");
    puts("#==================");
    puts("#");
    puts("# AES module");
    puts("#");
    puts("# (c) 2026 kok3shi");
    puts("#");
    puts("#====  Made by  ===");
    puts("# kok3shi");
    puts("#==================");
    
    command_register("aes_8a3", "show hw 0x8a3 key", (void*)show_aes_key_8a3);
    command_register("aes_8a4", "show hw 0x8a4 key", (void*)show_aes_key_8a4);
    command_register("kern_c1bt", "show current krn.c1bt", (void*)show_current_c1bt);
}
const char *module_name = "aes-key-v0";

struct pongo_exports exported_symbols[] =
{
    { .name = NULL, .value = NULL },
};
