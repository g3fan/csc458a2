/*
 *  Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
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

/**
 * sr_protocol.h
 *
 */

#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif



/* FIXME
 * ohh how lame .. how very, very lame... how can I ever go out in public
 * again?! /mc
 */

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif

#define ICMP_DATA_SIZE 28
#define ETHER_ADDR_LEN 6
#define sr_IFACE_NAMELEN 32
#define INIT_TTL 255

/* 
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;
typedef struct sr_ethernet_hdr sr_ethernet_hdr_t;


/*
 * Structure of an internet header, naked of options.
 */
struct sr_ip_hdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;   /* header length */
    unsigned int ip_v:4;    /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;    /* version */
    unsigned int ip_hl:4;   /* header length */
#else
#error "Byte ordering ot specified " 
#endif 
    uint8_t ip_tos;     /* type of service */
    uint16_t ip_len;      /* total length */
    uint16_t ip_id;     /* identification */
    uint16_t ip_off;      /* fragment offset field */
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    uint8_t ip_ttl;     /* time to live */
    uint8_t ip_p;     /* protocol */
    uint16_t ip_sum;      /* checksum */
    uint32_t ip_src, ip_dst;  /* source and dest address */
  } __attribute__ ((packed)) ;
typedef struct sr_ip_hdr sr_ip_hdr_t;


struct sr_arp_hdr
{
    unsigned short  ar_hrd;             /* format of hardware address   */
    unsigned short  ar_pro;             /* format of protocol address   */
    unsigned char   ar_hln;             /* length of hardware address   */
    unsigned char   ar_pln;             /* length of protocol address   */
    unsigned short  ar_op;              /* ARP opcode (command)         */
    unsigned char   ar_sha[ETHER_ADDR_LEN];   /* sender hardware address      */
    uint32_t        ar_sip;             /* sender IP address            */
    unsigned char   ar_tha[ETHER_ADDR_LEN];   /* target hardware address      */
    uint32_t        ar_tip;             /* target IP address            */
} __attribute__ ((packed)) ;
typedef struct sr_arp_hdr sr_arp_hdr_t;


/* Sizes in bytes */
#define ETHERNET_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define DATAGRAM_SIZE 8

/* Structure of a ICMP header
 */
struct sr_icmp_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  
} __attribute__ ((packed)) ;
typedef struct sr_icmp_hdr sr_icmp_hdr_t;

/* Structure of a ICMP header for NAT purposes
 */
struct sr_icmp_nat_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t id;
  uint16_t seq;
} __attribute__ ((packed)) ;
typedef struct sr_icmp_nat_hdr sr_icmp_nat_hdr_t;


/* Structure of a type3 ICMP header
 */
struct sr_icmp_t3_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t3_hdr sr_icmp_t3_hdr_t;

/* Structure of a type3 ICMP header
 */
struct sr_tcp_hdr {
  uint16_t port_src;
  uint16_t port_dst;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t protocol;
  unsigned int offset:4;
  unsigned int reserved:6;
  unsigned char urg;
  unsigned char ack;
  unsigned char psh;
  unsigned char rst;
  unsigned char syn;
  unsigned char fin;
  uint16_t window;
  uint16_t tcp_sum;
  uint16_t urgent;
  uint32_t options;
} __attribute__ ((packed)) ;
typedef struct sr_tcp_hdr sr_tcp_hdr_t;

/* Structure of a tcp pseudo header for use in tcp checksum calculation
 */
struct sr_tcp_pseudo_hdr {
  uint32_t ip_src;
  uint32_t ip_dst;
#define TCP_PSEUDO_RF 0x00      /* reserved fragment flag */
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_length;
} __attribute__ ((packed)) ;
typedef struct sr_tcp_pseudo_hdr sr_tcp_pseudo_hdr_t;

enum sr_ip_protocol {
  ip_protocol_icmp = 0x0001,
  ip_protocol_tcp = 0x0006,
  ip_protocol_udp = 0x0011,
};

enum sr_icmp_type {
  icmp_type_echo_reply = 0x0000,
  icmp_type_dest_unreachable = 0x0003,
  icmp_type_echo_request = 0x0008,
  icmp_time_exceeded = 0x000b, /* 11 in decimal */
};

enum sr_icmp_code {
  icmp_code_0 = 0x0000,
  icmp_code_1 = 0x0001,
  icmp_code_2 = 0x0002,
  icmp_code_3 = 0x0003,
};

enum sr_ethertype {
  ethertype_arp = 0x0806,
  ethertype_ip = 0x0800,
};

enum sr_arp_opcode {
  arp_op_request = 0x0001,
  arp_op_reply = 0x0002,
};

enum sr_arp_hrd_fmt {
  arp_hrd_ethernet = 0x0001,
};


struct sr_object
{
  uint8_t *packet;
  unsigned int len;
} __attribute__ ((packed)) ;
typedef struct sr_object sr_object_t;


#endif /* -- SR_PROTOCOL_H -- */
