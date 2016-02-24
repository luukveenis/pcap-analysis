#ifndef UTIL_H_
#define UTIL_H_

#define MAX_STR_LEN 120
#define MAX_NUM_CONNECTION 1000
#define MAX_PACKETS 2000

#include <stdint.h>
#include <netinet/tcp.h>

struct packet {
  int con_id;
  char ip_src[MAX_STR_LEN];
  char ip_dst[MAX_STR_LEN]; /* destination ip */
  uint16_t port_src;        /* source port number */
  uint16_t port_dst;        /* destination port number */
  tcp_seq seq;
  tcp_seq ackn;
  u_int16_t syn:1;
  u_int16_t ack:1;
  u_int16_t fin:1;
  u_int16_t rst:1;
};

struct connection {
  int id;
  int plen;   /* number of packets in connection */
  int psent;  /* number of packets sent from client to server */
  int precvd; /* number of packets received by client from server */
  struct packet *packets[MAX_PACKETS];
  char ip_src[MAX_STR_LEN]; /* source ip */
  char ip_dst[MAX_STR_LEN]; /* destination ip */
  uint16_t port_src;        /* source port number */
  uint16_t port_dst;        /* destination port number */
  uint16_t synstate;
  uint16_t finstate;
};

struct result {
  int packets;    /* Total number of packets sent */
  int cons_len;   /* Total number of connections */
  struct connection* cons[MAX_NUM_CONNECTION];
};


const char* timestamp_str(struct timeval);
void problem_pkt(struct timeval, const char*);
void pkt_too_short(struct timeval, const char*);
void print_results(struct result);

#endif
