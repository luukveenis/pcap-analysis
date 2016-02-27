#include <stdio.h>
#include <string.h>
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
  long xsec = x->tv_sec, xusec = x->tv_usec;
  long ysec = y->tv_sec, yusec = y->tv_usec;
  if (xusec < yusec) {
    int nsec = (yusec - xusec) / 1000000 + 1;
    yusec -= 1000000 * nsec;
    ysec += nsec;
  }
  if (xusec - yusec > 1000000) {
    int nsec = (xusec - yusec) / 1000000;
    yusec += 1000000 * nsec;
    ysec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = xsec - ysec;
  result->tv_usec = xusec - yusec;

  /* Return 1 if result is negative. */
  return xsec < ysec;
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
      timeval_subtract(&result, &(con->end), &(con->start));
      con->duration = result;
    }
  }
}

/* Get the size of the data sent from the client to the server or vice versa
 * If sent is non-zero, return the data size sent from client to server
 * If sent is zero, return the data size received from the server
 * */
int data_size(struct connection *con, int sent) {
  int i, sum = 0;
  struct packet *pkt;

  for (i = 0; i < con->plen; i++) {
    pkt = con->packets[i];
    /* Sum only the data size of packets going in the right direction */
    if (sent) {
      if (!strcmp(con->ip_src, pkt->ip_src)) {
        sum += con->packets[i]->datalen;
      }
    } else {
      if (!strcmp(con->ip_src, pkt->ip_dst)) {
        sum += con->packets[i]->datalen;
      }
    }
  }
  return sum;
}

struct tcp_data count_tcp_data(struct result res) {
  struct connection *con;
  struct timeval ts;
  uint16_t winsize;
  long micros = 0; /* Add up time in microseconds then convert back to timeval */
  long wmeansum = 0; /* We need a long to sum window sizes in */
  struct tcp_data data = { .mintime = { 0, 0 }, .maxtime = { 0, 0 } };
  int i, j, windows, ftime = 1;

  for (i = 0; i < res.cons_len; i++) {
    con = res.cons[i];
    if (con->reset) data.reset += 1;
    if (con->finstate == 0) data.open += 1;
    if (is_complete(con)) {
      data.complete += 1;
      data.pmean += con->plen;
      if (data.pmin == 0 || con->plen < data.pmin) data.pmin = con->plen;
      if (con->plen > data.pmax) data.pmax = con->plen;
      micros += con->duration.tv_usec + (con->duration.tv_sec * 1000000);
      if (ftime || !timeval_subtract(&ts, &data.mintime, &(con->duration))) {
        ftime = 0;
        data.mintime = con->duration;
      }
      if (timeval_subtract(&ts, &data.maxtime, &(con->duration))) {
        data.maxtime = con->duration;
      }
      for (j = 0; j < con->plen; j++) {
        winsize = con->packets[j]->window;
        windows++;
        wmeansum += winsize;
        if (winsize < data.wmin) data.wmin = winsize;
        if (winsize > data.wmax) data.wmax = winsize;
      }
    }
  }
  micros = micros / data.complete;
  ts.tv_sec = micros / 1000000;
  ts.tv_usec = micros % 999999;

  data.meantime = ts;
  data.pmean /= data.complete;
  data.wmean = wmeansum / windows;
  printf("wmean: %d\n", data.wmean);
  return data;
}

/* Computes round trip times for each connection and stores them */
void update_rtts(struct result *res) {
  int i,j,k, first = 1;
  long micros, rttcount;
  struct timeval start, end, result;
  struct connection *con;
  struct packet *pkt;

  /* Loop over all the connections */
  for (i = 0; i < res->cons_len; i++) {
    con = res->cons[i];
    if (is_complete(con)) {
      /* Loop over the packets for the connection */
      for (j = 0; j < con->plen; j++){
        pkt = con->packets[j];
        start = pkt->ts;
        /* Look for the matching Ack # to the Seq # */
        for (k = j + 1; k < con->plen; k++) {
          if (con->packets[k]->ack == pkt->seq) {
            end = con->packets[k]->ts; // grab the timestamp from the matching packet
            timeval_subtract(&result, &end, &start); // compute the RTT
            rttcount++; // keep track of how many RTT values we've computed
            micros += (result.tv_sec * 1000000 + result.tv_usec); // Store RTT sum in microseconds
            if (first || !timeval_subtract(&result, &res->minrtt, &end)) {
              first = 0;
              res->minrtt = end;
            }
            if (timeval_subtract(&result, &res->maxrtt, &end)) {
              res->maxrtt = end;
            }
            break;
          }
        }
      }
    }
  }
  /* Get the mean RTT value and convert it back to a timeval struct */
  micros /= rttcount;
  result.tv_sec = micros / 1000000;
  result.tv_usec = micros % 999999;
  res->meanrtt = result;
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
      int bsent = data_size(con, 1);
      int brcvd = data_size(con, 0);
      printf("Connection start time: %s\n", timestamp_str(con->start));
      printf("Connection end time: %s\n", timestamp_str(con->end));
      printf("Connection duration: %s\n", timestamp_str(con->duration));
      printf("Number of packets sent from source to destination: %d\n", con->psent);
      printf("Number of packets sent from destination to source: %d\n", con->precvd);
      printf("Total number of packets: %d\n", con->plen);
      printf("Number of data bytes sent from Source to Destination: %d\n", bsent);
      printf("Number of data bytes sent from Destination to Source: %d\n", brcvd);
      printf("Total data bytes sent: %d\n", (bsent + brcvd));
    }
    printf("END\n");
    if (i != res.cons_len - 1) printf("+++++++++++++++++++++++++++++\n");
  }
  printf("--------------------------------------------------------\n\n");
  printf("C) General:\n\n");
  struct tcp_data data = count_tcp_data(res);
  printf("Total number of complete TCP connections: %d\n", data.complete);
  printf("Number of reset TCP connections: %d\n", data.reset);
  printf("Number of TCP connections that were still open when the trace capture ended: %d\n", data.open);
  printf("\n--------------------------------------------------------\n\n");
  printf("D) Complete TCP Connections\n\n");
  printf("Minimum time duration: %s\n", timestamp_str(data.mintime));
  printf("Mean time duration: %s\n", timestamp_str(data.meantime));
  printf("Maximum time duration: %s\n\n", timestamp_str(data.maxtime));
  printf("Minimum RTT values including both send/received: %s\n", timestamp_str(res.minrtt));
  printf("Mean RTT values including both send/received: %s\n", timestamp_str(res.meanrtt));
  printf("Max RTT values including both send/received: %s\n\n", timestamp_str(res.maxrtt));
  printf("Minimum number of packets including both send/received: %d\n", data.pmin);
  printf("Mean number of packets including both send/received: %d\n", data.pmean);
  printf("Max number of packets including both send/received: %d\n\n", data.pmax);
  printf("Minimum receive window sizes including both send/received: %d\n", data.wmin);
  printf("Mean receive window sizes including both send/received: %d\n", data.wmean);
  printf("Maximum receive window sizes including both send/received: %d\n", data.wmax);
}
