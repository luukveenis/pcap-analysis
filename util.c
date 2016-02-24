#include <stdio.h>
#include <pcap.h>

#include "util.h"

/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char* timestamp_str(struct timeval ts) {
  static char timestamp_string_buf[256];
  sprintf(timestamp_string_buf, "%d.%06d", (int) ts.tv_sec, (int) ts.tv_usec);

  return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason) {
  fprintf(stderr, "%s: %s\n", timestamp_str(ts), reason);
}

void pkt_too_short(struct timeval ts, const char *truncated_hdr) {
  fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
    timestamp_str(ts), truncated_hdr);
}

int is_complete(struct connection *con){
  if ((con->synstate == 1 || con->synstate == 2) &&
      (con->finstate == 1 || con->finstate == 2)) {
    return 1;
  } else {
    return 0;
  }
}

void print_results(struct result res) {
  int i;
  printf("A) Total number of connections: %d\n", res.cons_len);
  printf("--------------------------------------------------------\n");
  printf("B) Connections' details:\n\n");
  for (i = 0; i < res.cons_len; i++) {
    struct connection *con = res.cons[i];
    printf("Connection %d\n", con->id);
    printf("Source address: %s\n", con->ip_src);
    printf("Destination address: %s\n", con->ip_dst);
    printf("Source port: %d\n", con->port_src);
    printf("Destination port: %d\n", con->port_dst);
    printf("Status: S%dF%d\n", con->synstate, con->finstate);
    if (is_complete(con)) {
      printf("Number of packets sent from source to destination: %d\n", con->psent);
      printf("Number of packets sent from destination to client: %d\n", con->precvd);
      printf("Total number of packets: %d\n", con->plen);
    }
    printf("END\n");
    if (i != res.cons_len - 1) printf("+++++++++++++++++++++++++++++\n");
  }
  printf("--------------------------------------------------------\n");
}
