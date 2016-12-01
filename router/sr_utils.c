#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_if.h"

/* Creates the checksum of the first len bytes of _data*/
uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

uint16_t tcp_cksum (uint8_t *ip_packet) {
  struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t*)ip_packet;
  uint8_t *tcp_segment = (uint8_t*)(ip_packet + sizeof(sr_ip_hdr_t));

  uint16_t tcp_segment_len = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t); /* Size of the TCP Segment, not including pseudo header */

  /*creates psuedo header for TCP and calculate*/
  sr_object_t tcp_pseudo_hdr_wrapper = create_tcp_pseudo_hdr(ip_hdr->ip_src, ip_hdr->ip_dst, tcp_segment_len);
  sr_object_t data = create_combined_packet(tcp_pseudo_hdr_wrapper.packet, tcp_pseudo_hdr_wrapper.len,
    tcp_segment, tcp_segment_len);

  uint16_t checksum = cksum(data.packet, data.len);
  free(tcp_pseudo_hdr_wrapper.packet);
  free(data.packet);

  return checksum;
}

void increment_ttl (uint8_t *ip_packet, int increment) {
  struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t*)ip_packet;

  ip_hdr->ip_ttl += increment;
  ip_hdr->ip_sum = htons(0);
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

sr_object_t create_icmp_packet(uint8_t type, uint8_t code, uint8_t* data, unsigned int len) {
  unsigned int icmp_hdr_size = sizeof(sr_icmp_hdr_t);
  struct sr_icmp_hdr* icmp_header = malloc(icmp_hdr_size);
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;
  icmp_header->icmp_sum = htons(0);

  sr_object_t combined_packet = create_combined_packet((uint8_t*)icmp_header, icmp_hdr_size, data, len);
 
  /* Set checksum after combining the data as the icmp checksum has to account for its misc. payload */
  sr_icmp_hdr_t *combined_header = (sr_icmp_hdr_t *)combined_packet.packet;
  combined_header->icmp_sum = cksum(combined_packet.packet, combined_packet.len);

  free(icmp_header);

  return combined_packet;
}

sr_object_t create_icmp_t3_packet(uint8_t icmp_type, uint8_t icmp_code, uint8_t* ip_packet) {
  /* Create ICMP type 3 header */
  unsigned int icmp_t3_hdr_size = sizeof(sr_icmp_t3_hdr_t);
  struct sr_icmp_t3_hdr* icmp_t3_hdr = malloc(icmp_t3_hdr_size);
  icmp_t3_hdr->icmp_type = icmp_type;
  icmp_t3_hdr->icmp_code = icmp_code;
  icmp_t3_hdr->next_mtu = htons(0);
  icmp_t3_hdr->icmp_sum = htons(0);
  icmp_t3_hdr->unused = htons(0);

  /* Copy over ip header and 8bytes of datagram as per ICMP type 3/11 definition */
  memcpy(icmp_t3_hdr->data, ip_packet, ICMP_DATA_SIZE);
  icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, icmp_t3_hdr_size);

  return create_packet((uint8_t *)icmp_t3_hdr, icmp_t3_hdr_size);
}


sr_object_t create_ip_packet(uint8_t protocol, uint32_t ip_src, uint32_t ip_dst, uint8_t* data, unsigned int len) {

  unsigned int ip_hdr_size = sizeof(sr_ip_hdr_t);
  sr_ip_hdr_t* ip_header = malloc(ip_hdr_size); 
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0; /* Best effort*/
  ip_header->ip_len = htons(ip_hdr_size + len); /* Total length of header and data */
  ip_header->ip_id = htons(0); /* No ip fragments */
  ip_header->ip_off = htons(IP_DF); /* No ip fragments(offset) */
  ip_header->ip_ttl = INIT_TTL;
  ip_header->ip_p = protocol;
  ip_header->ip_src = ip_src; 
  ip_header->ip_dst = ip_dst;
  ip_header->ip_sum = htons(0);

  uint16_t checksum = cksum(ip_header, ip_hdr_size);
  ip_header->ip_sum = checksum;

  sr_object_t packet = create_combined_packet((uint8_t *) ip_header, ip_hdr_size, data, len);
  free(ip_header);
  
  return packet;
}

/* Set source ip, source MAC and target MAC of the ARP response header*/
sr_object_t create_arp_response_hdr(struct sr_arp_hdr *arp_hdr, unsigned char *src_mac, uint32_t src_ip, unsigned char *dest_mac, uint32_t dest_ip) {

  unsigned int size = sizeof(sr_arp_hdr_t);
  sr_arp_hdr_t *arp_reponse_hdr = malloc(size);
  memcpy(arp_reponse_hdr, arp_hdr, size);

  memcpy(arp_reponse_hdr->ar_sha, src_mac, ETHER_ADDR_LEN);
  arp_reponse_hdr->ar_sip = src_ip;
  memcpy(arp_reponse_hdr->ar_tha, dest_mac, ETHER_ADDR_LEN);
  arp_reponse_hdr->ar_tip = dest_ip;
  arp_reponse_hdr->ar_op = htons(arp_op_reply);

  return create_packet((uint8_t *)arp_reponse_hdr, size);
}

sr_object_t create_ethernet_packet(uint8_t* ether_shost, uint8_t* ether_dhost, uint16_t ethertype, uint8_t *data, unsigned int len) {
  unsigned int ethernet_hdr_size = sizeof(sr_ethernet_hdr_t);
  sr_ethernet_hdr_t* output = malloc(ethernet_hdr_size);

  memcpy(output->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
  memcpy(output->ether_shost, ether_shost, ETHER_ADDR_LEN);
  output->ether_type = htons(ethertype);

  sr_object_t packet = create_combined_packet((uint8_t *) output, ethernet_hdr_size, data, len);
  free(output);

  return packet;
}

sr_object_t create_tcp_pseudo_hdr(uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_length) {
  unsigned int pseudo_hdr_size = sizeof(sr_tcp_pseudo_hdr_t);

  sr_tcp_pseudo_hdr_t *output = malloc(pseudo_hdr_size);
  output->ip_src = ip_src;
  output->ip_dst = ip_dst;
  output->reserved = TCP_PSEUDO_RF;
  output->protocol = ip_protocol_tcp;
  output->tcp_length = htons(tcp_length);

  return create_packet((uint8_t *)output, pseudo_hdr_size);
}

sr_object_t create_packet(uint8_t *packet, unsigned int len) {
  sr_object_t output;
  output.packet = packet;
  output.len = len;
  return output;
}

sr_object_t create_combined_packet(uint8_t *hdr, unsigned int hdr_len, uint8_t *data, unsigned int data_len) {
  sr_object_t output;
  uint8_t *combinedPacket = malloc(hdr_len + data_len);
  memcpy(combinedPacket, hdr, hdr_len);
  memcpy(combinedPacket + hdr_len, data, data_len);
  
  output.packet = combinedPacket;
  output.len = hdr_len + data_len;

  return output;
}
   
struct sr_rt* get_longest_prefix_match_interface(struct sr_rt *routingTable, uint32_t targetIP) {
  /* Target IP should be hardware */
    struct sr_rt* currRTEntry = routingTable;
    uint32_t longestMask = 0;
    struct sr_rt* output = NULL;

    while(currRTEntry) {
        if(targetIPMatchesEntry(currRTEntry->dest.s_addr, currRTEntry->mask.s_addr, targetIP) == 1){ 
            /* Always use longest mask, taking into account default route mask = 0 */
            if(ntohl((uint32_t)currRTEntry->mask.s_addr) >= ntohl(longestMask)) {
                longestMask = (uint32_t)currRTEntry->mask.s_addr;
                output = currRTEntry;
            }
        }
        currRTEntry = currRTEntry->next;
    }
    return output;
}

/*returns 1 for true, 0 for false*/
/*check what the mask actually is*/
int targetIPMatchesEntry(uint32_t entry, uint32_t mask, uint32_t target) {
    if((entry & mask) == (target & mask)) {
        return 1;
    }
    return 0;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out fields in TCP header. */
void print_hdr_tcp(uint8_t *buf) {
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *)(buf);

  fprintf(stderr, "TCP header:\n");
  fprintf(stderr, "\tsource port: %d\n", ntohs(tcphdr->port_src));
  fprintf(stderr, "\tdestination port: %d\n", ntohs(tcphdr->port_dst));
  fprintf(stderr, "\tsequence number: %d\n", ntohl(tcphdr->seq_num));
  fprintf(stderr, "\tack number: %d\n", ntohl(tcphdr->ack_num));
  fprintf(stderr, "\tprotocol: %d\n", tcphdr->protocol);
  fprintf(stderr, "\toffset: %d\n", tcphdr->offset);
  fprintf(stderr, "\treserved: %d\n", tcphdr->reserved);
  fprintf(stderr, "\tecn: %d\n", tcphdr->ecn);
  fprintf(stderr, "\tack: %d\n", tcphdr->urg);
  fprintf(stderr, "\tpsh: %d\n", tcphdr->psh);
  fprintf(stderr, "\trst: %d\n", tcphdr->rst);
  fprintf(stderr, "\tsyn: %d\n", tcphdr->syn);
  fprintf(stderr, "\tfin: %d\n", tcphdr->fin);
  fprintf(stderr, "\twindow: %d\n", ntohs(tcphdr->window));
  fprintf(stderr, "\tchecksum: %d\n", tcphdr->tcp_sum);
  fprintf(stderr, "\turgent: %d\n", ntohs(tcphdr->urgent));
  fprintf(stderr, "\toptions: %d\n", ntohl(tcphdr->options));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    } else if (ip_proto == ip_protocol_tcp) {
      minlength += sizeof(sr_tcp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print TCP header, insufficient length\n");
      else
        print_hdr_tcp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}
