#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#include "util.h"

/* ---------------- Function Definitions ----------------*/
int process_file(pcap_t*, struct result*);
struct packet* process_packet(const u_char*, struct timeval, unsigned int);


/* ---------------- Main ----------------*/
int main(int argc, char **argv) {
  struct result res;
  char err[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  /* We expect exactly one command line argument, the .cap file name */
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <capture-file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Try to open the file for processing */
  handle = pcap_open_offline(argv[1], err);
  if (handle == NULL) {
    fprintf(stderr,"%s\n", err);
    exit(EXIT_FAILURE);
  }

  /* Parse the contents of the file */
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
  struct packet *pkt;
  const u_char *packet;

  while (packet = pcap_next(handle, &header)){
    pkt = process_packet(packet, header.ts, header.caplen);
    printf("---------- PACKET ----------\n");
    printf("IP src: %s\n", pkt->ip_src);
    printf("IP dst: %s\n", pkt->ip_dst);
    printf("src port: %d\n", pkt->port_src);
    printf("dst port: %d\n", pkt->port_dst);
    printf("----------------------------\n\n");
    free(pkt);
  }

  return 0;
}

/* Parser a packet containing ethernet, IP, and TCP headers and returns a
 * data structure that contains the information relevant to this assignment. */
struct packet* process_packet(const u_char *packet, struct timeval ts, unsigned int caplen) {
  struct ip *ip;
  struct tcphdr *tcp;
  unsigned int iphdrlen;

  /* Didn't capture the full ethernet header */
  if (caplen < sizeof(struct ether_header)) {
    pkt_too_short(ts, "Ethernet header");
    return NULL;
  }

  /* Skip over the Ethernet header. */
  packet += sizeof(struct ether_header);
  caplen -= sizeof(struct ether_header);

  /* Didn't capture a full IP header */
  if (caplen < sizeof(struct ip)) {
    pkt_too_short(ts, "IP header");
    return NULL;
  }

  ip = (struct ip*) packet;
  iphdrlen = ip->ip_hl * 4; // ip_hl is in 4-byte words

  /* Didn't capture the full IP header with options */
  if (caplen < iphdrlen) {
    pkt_too_short(ts, "IP header with options");
    return NULL;
  }

  /* Ignore non-TCP packets */
  if (ip->ip_p != IPPROTO_TCP) {
    problem_pkt(ts, "non-TCP packet");
    return NULL;
  }

  /* Get the IPs and skip to the TCP header */
  struct packet* pkt = malloc(sizeof(struct packet));
  strcpy(pkt->ip_src, inet_ntoa(ip->ip_src));
  strcpy(pkt->ip_dst, inet_ntoa(ip->ip_dst));
  packet += iphdrlen;
  caplen -= iphdrlen;

  /* Didn't capture the full TCP header */
  if (caplen < sizeof(struct tcphdr)) {
    pkt_too_short(ts, "TCP header");
    return NULL;
  }

  /* Extract the source and destination port */
  tcp = (struct tcphdr*) packet;
  pkt->port_src = ntohs(tcp->th_sport);
  pkt->port_dst = ntohs(tcp->th_dport);

  return pkt;
}
