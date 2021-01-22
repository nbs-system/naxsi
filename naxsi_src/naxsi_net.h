/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) NBS System – All Rights Reserved
 * Licensed under GNU GPL v3.0 – See the LICENSE notice for details
 */

#ifndef __NAXSI_NET_H__
#define __NAXSI_NET_H__

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

typedef union
{
  uint64_t v6[2];
  uint32_t v4;
} ip_t;

typedef enum
{
  IPv4 = 0,
  IPv6
} ip_type_t;

typedef struct
{
  uint32_t version;
  ip_t     mask;
  ip_t     subnet;
} cidr_t;

int
parse_ipv6(const char* addr, ip_t* ip, char* ip_str);
int
parse_ipv4(const char* addr, ip_t* ip, char* ip_str);

int
is_in_subnet(const cidr_t* cidr, const ip_t* ip, int is_ipv6);

#endif /* __NAXSI_NET_H__ */
