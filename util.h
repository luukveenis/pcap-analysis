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
  struct timeval ts;        /* timestamp */
  u_short datalen;
  tcp_seq seq;
  tcp_seq ackn;
  uint16_t window;
  uint16_t syn:1;
  uint16_t ack:1;
  uint16_t fin:1;
  uint16_t rst:1;
};

struct connection {
  int id;
  struct timeval start;
  struct timeval end;
  struct timeval duration;
  int plen;    /* number of packets in connection */
  int psent;   /* number of packets sent from client to server */
  int precvd;  /* number of packets received by client from server */
  int dsent;   /* data bytes sent */
  int drcvd;   /* data bytes received */
  int reset:1; /* 1 if connection has been reset, 0 otherwise */
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

struct tcp_data {
  int reset;
  int complete;
  int open;
  struct timeval mintime;
  struct timeval meantime;
  struct timeval maxtime;
  int pmin;
  int pmean;
  int pmax;
  uint16_t wmin;
  uint16_t wmean;
  uint16_t wmax;
};

const char* timestamp_str(struct timeval);
void problem_pkt(struct timeval, const char*);
void pkt_too_short(struct timeval, const char*);
void print_results(struct result);

#endif
