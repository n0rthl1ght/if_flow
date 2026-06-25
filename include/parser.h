#ifndef IF_FLOW_PARSER_H
#define IF_FLOW_PARSER_H

#include <stddef.h>
#include <stdint.h>

int parser_extract_tls_sni(const uint8_t *payload, size_t len, char *out, size_t out_sz);
int parser_extract_http_host(const uint8_t *payload, size_t len, char *out, size_t out_sz);

#endif
