#ifndef IF_FLOW_LOCAL_IP_H
#define IF_FLOW_LOCAL_IP_H

#include <stddef.h>

typedef struct {
    /* All IPv4/IPv6 addresses currently assigned to the local host. */
    char **items;
    size_t len;
    size_t cap;
} local_ip_list_t;

void local_ip_list_init(local_ip_list_t *list);
void local_ip_list_free(local_ip_list_t *list);
int local_ip_list_load(local_ip_list_t *list);
int local_ip_list_contains(const local_ip_list_t *list, const char *ip);

#endif
