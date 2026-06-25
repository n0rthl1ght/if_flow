#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "parser.h"

/* Tiny case-insensitive bounded search used for HTTP header extraction. */
static const char *memcasestr_n(const char *hay, size_t hay_len, const char *needle) {
    size_t i;
    size_t nl = strlen(needle);
    if (nl == 0 || hay_len < nl) return NULL;
    for (i = 0; i + nl <= hay_len; ++i) {
        size_t j = 0;
        while (j < nl) {
            char a = (char)tolower((unsigned char)hay[i + j]);
            char b = (char)tolower((unsigned char)needle[j]);
            if (a != b) break;
            ++j;
        }
        if (j == nl) return hay + i;
    }
    return NULL;
}

int parser_extract_tls_sni(const uint8_t *payload, size_t len, char *out, size_t out_sz) {
    size_t p;
    uint8_t sid_len;
    uint16_t cs_len;
    uint8_t comp_len;
    uint16_t ext_len;
    size_t ex;
    size_t ex_end;

    /*
     * This is intentionally a minimal TLS ClientHello parser. We only walk far
     * enough to extract SNI and immediately stop; full TLS decoding is out of
     * scope for a low-overhead flow collector.
     */
    if (!payload || !out || out_sz == 0) return 0;
    out[0] = '\0';
    if (len < 9 || payload[0] != 0x16 || payload[5] != 0x01) return 0;

    p = 9;
    if (p + 2 + 32 > len) return 0;
    p += 2 + 32;

    if (p + 1 > len) return 0;
    sid_len = payload[p++];
    if (p + sid_len > len) return 0;
    p += sid_len;

    if (p + 2 > len) return 0;
    cs_len = ((uint16_t)payload[p] << 8) | payload[p + 1];
    p += 2;
    if (p + cs_len > len) return 0;
    p += cs_len;

    if (p + 1 > len) return 0;
    comp_len = payload[p++];
    if (p + comp_len > len) return 0;
    p += comp_len;

    if (p + 2 > len) return 0;
    ext_len = ((uint16_t)payload[p] << 8) | payload[p + 1];
    p += 2;
    if (p + ext_len > len) return 0;

    ex = p;
    ex_end = p + ext_len;
    while (ex + 4 <= ex_end) {
        uint16_t typ = ((uint16_t)payload[ex] << 8) | payload[ex + 1];
        uint16_t ln = ((uint16_t)payload[ex + 2] << 8) | payload[ex + 3];
        ex += 4;
        if (ex + ln > ex_end) break;
        if (typ == 0x0000 && ln >= 2) {
            size_t q = ex + 2;
            size_t q_end = ex + ln;
            while (q + 3 <= q_end) {
                uint8_t nt = payload[q++];
                uint16_t nln = ((uint16_t)payload[q] << 8) | payload[q + 1];
                q += 2;
                if (q + nln > q_end) break;
                if (nt == 0x00 && nln > 0 && nln < out_sz) {
                    memcpy(out, &payload[q], nln);
                    out[nln] = '\0';
                    return 1;
                }
                q += nln;
            }
        }
        ex += ln;
    }
    return 0;
}

int parser_extract_http_host(const uint8_t *payload, size_t len, char *out, size_t out_sz) {
    const char *p;
    const char *h;
    const char *e;
    size_t n;
    /*
     * HTTP host extraction is best-effort and tolerant to mixed header casing.
     * It is only used as a naming hint for otherwise generic TCP/HTTP flows.
     */
    if (!payload || !out || out_sz == 0) return 0;
    out[0] = '\0';
    if (len < 8) return 0;
    p = (const char *)payload;
    h = memcasestr_n(p, len, "\r\nHost:");
    if (!h) h = memcasestr_n(p, len, "\nhost:");
    if (!h) h = memcasestr_n(p, len, "Host:");
    if (!h) return 0;
    h = strchr(h, ':');
    if (!h) return 0;
    ++h;
    while ((size_t)(h - p) < len && (*h == ' ' || *h == '\t')) ++h;
    e = h;
    while ((size_t)(e - p) < len && *e != '\r' && *e != '\n') ++e;
    n = (size_t)(e - h);
    if (n == 0 || n >= out_sz) return 0;
    memcpy(out, h, n);
    out[n] = '\0';
    while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t')) out[--n] = '\0';
    return n > 0;
}
