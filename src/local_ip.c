#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local_ip.h"

/* Direction detection depends on a deduplicated snapshot of the host's own IPs. */
static int local_ip_list_add(local_ip_list_t *list, const char *ip) {
    size_t i;
    char **new_items;

    if (!list || !ip || !*ip) return 0;

    for (i = 0; i < list->len; ++i) {
        if (strcmp(list->items[i], ip) == 0) return 1;
    }

    if (list->len == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 32;
        new_items = (char **)realloc(list->items, new_cap * sizeof(*new_items));
        if (!new_items) return 0;
        list->items = new_items;
        list->cap = new_cap;
    }

    list->items[list->len] = strdup(ip);
    if (!list->items[list->len]) return 0;
    list->len++;
    return 1;
}

void local_ip_list_init(local_ip_list_t *list) {
    if (!list) return;
    memset(list, 0, sizeof(*list));
}

void local_ip_list_free(local_ip_list_t *list) {
    size_t i;
    if (!list) return;
    for (i = 0; i < list->len; ++i) free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->len = 0;
    list->cap = 0;
}

int local_ip_list_load(local_ip_list_t *list) {
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa;
    char ipbuf[INET6_ADDRSTRLEN];

    if (!list) return -1;
    if (getifaddrs(&ifaddr) != 0) return -1;

    /*
     * The list is loaded once at startup. That is sufficient for the intended
     * deployment model where interface changes are relatively rare.
     */
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        void *addr_ptr = NULL;

        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            addr_ptr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
        } else {
            continue;
        }

        if (!inet_ntop(ifa->ifa_addr->sa_family, addr_ptr, ipbuf, sizeof(ipbuf))) continue;
        local_ip_list_add(list, ipbuf);
    }

    freeifaddrs(ifaddr);
    return 0;
}

int local_ip_list_contains(const local_ip_list_t *list, const char *ip) {
    size_t i;
    if (!list || !ip) return 0;
    for (i = 0; i < list->len; ++i) {
        if (strcmp(list->items[i], ip) == 0) return 1;
    }
    return 0;
}
