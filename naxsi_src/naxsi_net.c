#include "naxsi_net.h"

int
parse_ipv6(const char* addr, ip_t* ip, char* ip_str)
{
  struct in6_addr ipv6 = { .s6_addr = { 0 } };
  if (inet_pton(AF_INET6, addr, &ipv6) != 1) {
    return 0;
  }

  if (ip) {
    // ipv6 hi
    ip->v6[0] = ipv6.s6_addr[0];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[1];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[2];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[3];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[4];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[5];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[6];
    ip->v6[0] = (ip->v6[0] << 8) | ipv6.s6_addr[7];

    // ipv6 low
    ip->v6[1] = ipv6.s6_addr[8];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[9];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[10];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[11];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[12];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[13];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[14];
    ip->v6[1] = (ip->v6[1] << 8) | ipv6.s6_addr[15];
  }

  if (ip_str) {
    inet_ntop(AF_INET6, &ipv6, ip_str, INET6_ADDRSTRLEN);
  }
  return 1;
}

int
parse_ipv4(const char* addr, ip_t* ip, char* ip_str)
{
  struct in_addr ipv4 = { .s_addr = 0 };
  if (inet_pton(AF_INET, addr, &ipv4) != 1) {
    return 0;
  }

  if (ip) {
    ip->v4 = htonl(ipv4.s_addr);
  }

  if (ip_str) {
    inet_ntop(AF_INET, &ipv4, ip_str, INET_ADDRSTRLEN);
  }
  return 1;
}

int
is_in_subnet(const cidr_t* cidr, const ip_t* ip, int is_ipv6)
{
  if ((cidr->version == IPv6 && !is_ipv6) || (cidr->version == IPv4 && is_ipv6)) {
    return 0;
  }
  if (cidr->version == IPv4) {
    return (ip->v4 & cidr->mask.v4) == (cidr->subnet.v4 & cidr->mask.v4);
  } else {
    return (ip->v6[0] & cidr->mask.v6[0]) == (cidr->subnet.v6[0] & cidr->mask.v6[0]) &&
           (ip->v6[1] & cidr->mask.v6[1]) == (cidr->subnet.v6[1] & cidr->mask.v6[1]);
  }
  return 0;
}