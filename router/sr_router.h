/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;

    struct sr_nat nat;

    FILE* logfile;
};

struct thread_input{
  struct sr_instance* sr;
  uint8_t* packet;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance*, int useNat, unsigned int icmp_timeout, unsigned int tcp_established_timeout, unsigned int tcp_transitory_timeout);
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

void sr_handle_arp_request(struct sr_instance* sr, struct sr_ethernet_hdr *ethernet_hdr, struct sr_arp_hdr *arp_hdr, struct sr_if* self_interface);
void sr_handle_packet_reply(struct sr_instance* sr, struct sr_ethernet_hdr* ethernet_hdr, uint8_t *ip_packet);
void sr_handle_packet_forward(struct sr_instance *sr, struct sr_if *incoming_interface, struct sr_ethernet_hdr *ethernet_hdr, uint8_t *ip_packet);

int sr_is_packet_recipient(struct sr_instance *sr, uint32_t ip);
int sr_ip_packet_is_valid(uint8_t *ip_packet, unsigned int ip_packet_len);

void queue_ethernet_packet(struct sr_instance *sr, uint8_t *ip_packet, unsigned int ip_packet_len, uint8_t* original_eth_src);
void sr_create_send_ethernet_packet(struct sr_instance* sr, uint8_t* ether_shost, uint8_t* ether_dhost, uint16_t ethertype, uint8_t *data, uint16_t len);
void createAndSendIPPacket(struct sr_instance* sr, uint32_t ip_src, uint32_t ip_dest, uint8_t* eth_src, uint8_t* eth_dest, uint8_t* ip_payload, uint8_t size);

sr_ethernet_hdr_t *sr_copy_ethernet_packet(uint8_t *ethernet_packet, unsigned int len);
struct sr_arp_hdr *sr_copy_arp_hdr(uint8_t *ethernet_packet);
uint8_t *sr_copy_ip_packet(uint8_t *ethernet_packet, unsigned int ip_packet_len);
uint8_t *sr_copy_icmp_packet(uint8_t *ip_packet, unsigned int ip_packet_len, unsigned int ip_hdr_len);
struct sr_if *sr_copy_interface(struct sr_if *interface);

/* -- NAT functions -- */
int sr_nat_is_packet_recipient(struct sr_instance *sr, struct sr_if* interface, uint8_t *ip_packet);

/*checks if we get a syn packet in 6 seconds, and sends ICMP port unreachable otherwise*/
/*input packet should include tcp header*/
void handle_unsolicited_syn(struct sr_instance* sr, uint8_t* packet);

/*thread that gets spawned to deal with unsolicited syn*/
void *unsolicited_syn_thread(void* input);

/*I am assuming the ethernet and ip packets are in network order*/
/* returns 1 for success, 0 means drop the packet*/
/*this functions modifies the passed in pointers*/
int sr_nat_handle_internal(struct sr_instance *sr, uint8_t *ip_packet);
int sr_nat_handle_external(struct sr_instance *sr, uint8_t *ip_packet);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
