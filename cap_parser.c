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
int check_connection(struct packet, struct result);
struct connection* new_connection(struct packet, struct result*);


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
  res.cons_len = 0;
  res.packets = 0;
  process_file(handle, &res);
  print_results(res);

  return 0;
}


/* Processes the contents of a capture file
 * Returns:
 *  -  0 for success
 *  - -1 for failure
 */
int process_file(pcap_t *handle, struct result *res){
  int con;
  struct connection *connection;
  struct pcap_pkthdr header;
  struct packet *pkt;
  const u_char *packet;

  while (packet = pcap_next(handle, &header)){
    res->packets++;
    pkt = process_packet(packet, header.ts, header.caplen);
    if (pkt != NULL) {
      con = check_connection(*pkt, *res);
      if (con == -1) {
        connection = new_connection(*pkt, res);
      }
      if (pkt->syn == 1) connection->synstate++;
      if (pkt->fin == 1) connection->finstate++;
      free(pkt);
    }
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
  pkt->seq = ntohl(tcp->th_seq);
  pkt->ackn = ntohl(tcp->th_ack);
  pkt->syn = tcp->syn;
  pkt->ack = tcp->ack;
  pkt->fin = tcp->fin;
  pkt->rst = tcp->rst;

  return pkt;
}

/* Returns the ID of the connection this packet belongs to; if this is a new
 * connection being discovered, we return -1.
 * We have to account for the fact that the source/destination might be swapped
 * since the packet can be going client->server OR server->client.
 */
int check_connection(struct packet pkt, struct result res) {
  int i;
  for (i = 0; i < res.cons_len; i++) {
    struct connection *con = res.cons[i];
    /* The source IPs match */
    if (!strcmp(pkt.ip_src, con->ip_src) && !strcmp(pkt.ip_dst, con->ip_dst) &&
        pkt.port_src == con->port_src && pkt.port_dst == con->port_dst) {
      return con->id;
    /* The packet source IP matches the connection destination IP */
    }
    if (!strcmp(pkt.ip_src, con->ip_dst) && !strcmp(pkt.ip_dst, con->ip_src) &&
        pkt.port_src == con->port_dst && pkt.port_dst == con->port_src) {
      return con->id;
    }
  }
  return -1;
}

/* Creates a new connection struct using the fields from the packet struct
 * provided and adds this connection to the result array. */
struct connection* new_connection(struct packet pkt, struct result *res) {
  struct connection *con = malloc(sizeof(struct connection));
  strcpy(con->ip_src, pkt.ip_src);
  strcpy(con->ip_dst, pkt.ip_dst);
  con->port_src = pkt.port_src;
  con->port_dst = pkt.port_dst;
  con->id = res->cons_len + 1;
  con->synstate = 0;
  con->finstate = 0;
  res->cons[res->cons_len] = con;
  res->cons_len++;

  return con;
}
