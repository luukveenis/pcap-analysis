#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_STR_LEN 120
#define MAX_NUM_CONNECTION 1000

struct connection {
  char ip_src[MAX_STR_LEN]; /* source ip */
  char ip_dst[MAX_STR_LEN]; /* destination ip */
  uint16_t port_src;        /* source port number */
  uint16_t port_dst;        /* destination port number */
};

struct result {
  int cons_len;
  struct connection cons[MAX_NUM_CONNECTION];
};

/* ---------------- Function Definitions ----------------*/
int process_file(pcap_t*, struct result*);


/* ---------------- Main ----------------*/
int main(int argc, char **argv) {
  struct result res;
  char err[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <capture-file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  handle = pcap_open_offline(argv[1], err);
  if (handle == NULL) {
    fprintf(stderr,"%s\n", err);
    exit(EXIT_FAILURE);
  }

  process_file(handle, &res);

  return 0;
}


/* Processes the contents of a capture file
 * Returns:
 *  -  0 for success
 *  - -1 for failure
 */
int process_file(pcap_t *handle, struct result *res){
  struct pcap_pkthdr header;
  const u_char *packet;

  while (packet = pcap_next(handle, &header)){
    /* process packets here */
  }

  return 0;
}
