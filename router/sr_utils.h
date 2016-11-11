/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

struct sr_if;

uint16_t cksum(const void *_data, int len);
uint16_t get_network_cksum_from_hardware_ip(uint8_t* ip_hdr, int len);
uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

/*originally from arpcache*/
sr_object_t create_icmp_packet(uint8_t type, uint8_t code, uint8_t* data, unsigned int len);
sr_object_t create_icmp_t3_packet(uint8_t icmp_type, uint8_t icmp_code, uint16_t next_mtu, uint8_t* ip_packet);
sr_object_t create_ip_packet( uint8_t protocol, uint32_t ip_src, uint32_t ip_dst, uint8_t* data, unsigned int len);
sr_object_t create_arp_response_hdr(struct sr_arp_hdr *arp_hdr, unsigned char *self_mac, uint32_t self_ip, unsigned char *target_mac, uint32_t target_ip);
sr_object_t create_ethernet_packet(uint8_t* ether_shost, uint8_t* ether_dhost, uint16_t ethertype, uint8_t *data, unsigned int len);

sr_object_t create_packet(uint8_t *packet, unsigned int len);
sr_object_t create_combined_packet(uint8_t *hdr, unsigned int hdr_len, uint8_t *data, unsigned int data_len);

struct sr_rt* get_longest_prefix_match_interface(struct sr_rt *routingTable, uint32_t targetIP);
int targetIPMatchesEntry(uint32_t entry, uint32_t mask, uint32_t target);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

#endif /* -- SR_UTILS_H -- */
