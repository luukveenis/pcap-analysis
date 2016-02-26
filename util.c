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

/* The following function `timeval_subtract` was taken from:
 * http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
 *
 * Subtract the ‘struct timeval’ values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

/* Set the connection start and end times for all complete connections */
void update_timestamps(struct result *res) {
  int i;
  struct connection *con;

  struct timeval start = res->cons[0]->packets[0]->ts;
  for (i = 0; i < res->cons_len; i++) {
    con = res->cons[i];
    /* Set connection start and end time relative to the first packet */
    if (is_complete(con)) {
      struct timeval result;
      timeval_subtract(&result, &(con->packets[0]->ts), &start);
      con->start = result;
      timeval_subtract(&result, &(con->packets[con->plen - 1]->ts), &start);
      con->end = result;
    }
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
      struct timeval duration;
      timeval_subtract(&duration, &(con->end), &(con->start));
      printf("Number of packets sent from source to destination: %d\n", con->psent);
      printf("Number of packets sent from destination to client: %d\n", con->precvd);
      printf("Connection start time: %s\n", timestamp_str(con->start));
      printf("Connection end time: %s\n", timestamp_str(con->end));
      printf("Connection duration: %s\n", timestamp_str(duration));
      printf("Total number of packets: %d\n", con->plen);
    }
    printf("END\n");
    if (i != res.cons_len - 1) printf("+++++++++++++++++++++++++++++\n");
  }
  printf("--------------------------------------------------------\n");
}
