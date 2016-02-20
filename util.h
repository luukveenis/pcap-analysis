#ifndef UTIL_H_
#define UTIL_H_

#define MAX_STR_LEN 120
#define MAX_NUM_CONNECTION 1000

struct packet {
  char ip_src[MAX_STR_LEN];
  char ip_dst[MAX_STR_LEN]; /* destination ip */
  uint16_t port_src;        /* source port number */
  uint16_t port_dst;        /* destination port number */
};

struct connection {
  int id;
  char ip_src[MAX_STR_LEN]; /* source ip */
  char ip_dst[MAX_STR_LEN]; /* destination ip */
  uint16_t port_src;        /* source port number */
  uint16_t port_dst;        /* destination port number */
};

struct result {
  int cons_len;
  struct connection cons[MAX_NUM_CONNECTION];
};


const char* timestamp_str(struct timeval);
void problem_pkt(struct timeval, const char*);
void pkt_too_short(struct timeval, const char*);

#endif
