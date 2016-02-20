#include <stdio.h>
#include <pcap.h>

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
