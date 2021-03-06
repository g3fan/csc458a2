/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr, int useNat, unsigned int icmp_timeout, unsigned int tcp_established_timeout,
  unsigned int tcp_transitory_timeout)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    sr_nat_init(&(sr->nat), useNat, icmp_timeout, tcp_established_timeout, tcp_transitory_timeout);

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    /* Add initialization code here! */
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t *packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  /* The ethernet packet*/
  assert(packet);
  /* The incoming interface*/
  assert(interface);

  /* fill in code here */

  sr_ethernet_hdr_t *ethernet_hdr = sr_copy_ethernet_packet(packet, len);
  /* Swap interface to hardware */
  struct sr_if* incoming_interface = sr_copy_interface(sr_get_interface(sr, interface));

  /* Separate logic into handling arp vs. ip packets*/
  if (ethernet_hdr->ether_type == htons(ethertype_arp)) {
    struct sr_arp_hdr *arp_hdr = sr_copy_arp_hdr((uint8_t *) ethernet_hdr);

    /* Only handle the arp packet if the router is the recipient */
    if (sr_is_packet_recipient(sr, arp_hdr->ar_tip)) {
      /* If ARP request, reply with our mac address*/
      if (arp_hdr->ar_op == htons(arp_op_request)) {
        sr_handle_arp_request(sr, ethernet_hdr, arp_hdr, incoming_interface);
      } else if (arp_hdr->ar_op == htons(arp_op_reply)) {
        /* If ARP response, remove the ARP request from the queue, update cache, forward any packets that were waiting on that ARP request
        all Gorden's function*/
        receivedARPReply(sr, arp_hdr);
      }
    }

    free(arp_hdr);
  } else if (ethernet_hdr->ether_type == htons(ethertype_ip)) {
    /* If receive an IP packet*/
    unsigned int ip_packet_len = len - sizeof(struct sr_ethernet_hdr);
    uint8_t *ip_packet = sr_copy_ip_packet((uint8_t *) ethernet_hdr, ip_packet_len);

    /* Check if the received packet is valid, if not drop the packet*/
    if (sr_ip_packet_is_valid(ip_packet, ip_packet_len)) {
      if (sr_nat_is_packet_recipient(sr, incoming_interface, ip_packet)) {
        sr_handle_packet_reply(sr, ethernet_hdr, ip_packet);
      } else { 
        sr_handle_packet_forward(sr, ethernet_hdr, ip_packet);
      }
    }

    free(ip_packet);
  }

  free(ethernet_hdr);
  free(incoming_interface);
}/* end sr_handlepacket */

/* Send back the MAC address of our incoming interface to the sender*/
void sr_handle_arp_request(struct sr_instance* sr, struct sr_ethernet_hdr *ethernet_hdr, struct sr_arp_hdr *arp_hdr, struct sr_if* out_interface) {

  sr_object_t arp_response_wrapper = create_arp_response_hdr(arp_hdr, out_interface->addr, out_interface->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
  
  sr_create_send_ethernet_packet(sr,
      out_interface->addr, 
      ethernet_hdr->ether_shost, 
      ethertype_arp, 
      (uint8_t *) arp_response_wrapper.packet, 
      sizeof(sr_arp_hdr_t));

  free(arp_response_wrapper.packet);
}

void sr_handle_packet_reply(struct sr_instance* sr, struct sr_ethernet_hdr* ethernet_hdr, uint8_t *ip_packet) {
  /* When replying, simply swap the original ip/mac values */
  struct sr_ip_hdr* ip_hdr = (sr_ip_hdr_t*) ip_packet;  
  uint32_t ip_src = ip_hdr->ip_dst;
  uint32_t ip_dest = ip_hdr->ip_src;
  uint8_t* eth_src = ethernet_hdr->ether_dhost;
  uint8_t* eth_dest = ethernet_hdr->ether_shost;
  sr_object_t icmp_wrapper;
  icmp_wrapper.packet = NULL;

  /* Return a port unreachable for UDP or TCP type packets through a icmp_t3_header*/
  if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
    icmp_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_3, ip_packet);
  } else if (ip_hdr->ip_p == ip_protocol_icmp) {
    /* Return a echo reply for echo request*/
    unsigned int headers_size = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t* icmp_payload = ip_packet + headers_size;
    unsigned int icmp_payload_len = ntohs(ip_hdr->ip_len) - headers_size;
    icmp_wrapper = create_icmp_packet(icmp_type_echo_reply, icmp_code_0, icmp_payload, icmp_payload_len);
  }

  /* Only perform replies when handling a valid reply action */
  if (icmp_wrapper.packet != NULL) {
    /* Determine the destination to reply to first through the arp cache */
    struct sr_rt* longestPrefixIPMatch = get_longest_prefix_match_interface(sr->routing_table, ip_hdr->ip_src);

    /* Send destination unreachable if reply destination is not in the forwarding table */
    if (longestPrefixIPMatch == NULL) {
      sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_0, ip_packet);
      createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);

      free(icmp_t3_wrapper.packet);
    } else {
      uint32_t nextHopIP = longestPrefixIPMatch->gw.s_addr;
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), nextHopIP);

      if (arp_entry == NULL) {
        /* Send an arp request if we do not have the reply destination cached */
        sr_object_t ip_wrapper = create_ip_packet(ip_protocol_icmp, ip_src, ip_dest, icmp_wrapper.packet, icmp_wrapper.len);
        sr_object_t eth_wrapper = create_ethernet_packet(eth_src, eth_dest, ethertype_ip, ip_wrapper.packet, ip_wrapper.len);
        sr_arpcache_queuereq(&(sr->cache), nextHopIP, eth_wrapper.packet, eth_wrapper.len, longestPrefixIPMatch->interface);

        free(ip_wrapper.packet);
        free(eth_wrapper.packet);
      } else {
        /* Send out reply normally if the destination is cached */
        struct sr_if* outgoing_interface = sr_get_interface(sr, longestPrefixIPMatch->interface);
        eth_src = outgoing_interface->addr;
        eth_dest = arp_entry->mac;

        createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_wrapper.packet, icmp_wrapper.len);
        free(arp_entry);
      }
    }
  }

  free(icmp_wrapper.packet);
}

void sr_handle_packet_forward(struct sr_instance *sr, struct sr_ethernet_hdr *ethernet_hdr, uint8_t *ip_packet) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  /* Initialize packet src/dest with 'reply' type values before NAT is applied as multiple cases involve sending back an
     icmp packet to the original source */
  struct sr_rt* reply_rt = get_longest_prefix_match_interface(sr->routing_table, ip_hdr->ip_src);

  if (reply_rt == NULL) {
    return;
  }

  struct sr_if *reply_interface = sr_get_interface(sr, reply_rt->interface);

  if (!reply_interface) {
    return;
  }

  uint32_t ip_dest = ip_hdr->ip_src;
  uint32_t ip_src = reply_interface->ip;
  uint8_t* eth_src = ethernet_hdr->ether_dhost;
  uint8_t* eth_dest = ethernet_hdr->ether_shost;

  uint8_t *forwarding_packet = ip_packet;
  int forwardNATPacket = 0;

  /* Apply NAT logic to the packet if it is active */
  if (sr->nat.is_active && ip_hdr->ip_ttl > 1) {
    /* NAT is only used in certain cases
       This occurs when, 1. External(source) to the external NAT interface (destination)
                         2. Internal(source) to external(destination) interface */
    if (sr_is_interface_external(reply_interface) && ip_hdr->ip_dst == sr->nat.external_if_ip) {
      forwardNATPacket = 1;
    } else if (sr_is_interface_internal(reply_interface)) {
      struct sr_rt* forward_rt = get_longest_prefix_match_interface(sr->routing_table, ip_hdr->ip_dst);

      if (forward_rt != NULL) {
        struct sr_if *forward_interface = sr_get_interface(sr, forward_rt->interface);

        forwardNATPacket = sr_is_interface_external(forward_interface);
      }
    }

    if (forwardNATPacket) {
      unsigned int ip_packet_len = ntohs(ip_hdr->ip_len);
      uint8_t *nat_packet = malloc(ip_packet_len);
      memcpy(nat_packet, ip_packet, ip_packet_len);

      /* forwarNATPacket, 1 = forward, 0 = don't forward, -1 = send port unreachable */
      if (sr_is_interface_internal(reply_interface)) {
        forwardNATPacket = sr_nat_handle_internal(sr, nat_packet);
      } else {
        forwardNATPacket = sr_nat_handle_external(sr, nat_packet);
      }

      if (forwardNATPacket == 0) {
        free(nat_packet);
        return;
      } else if (forwardNATPacket == -1) {
        /* Handle case of port unreachable */
        sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_3, ip_packet);
        createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);

        free(icmp_t3_wrapper.packet);
        free(nat_packet);
        return;
      }

      forwarding_packet = nat_packet;
    }
  }

  sr_ip_hdr_t *forwarding_ip_hdr = (sr_ip_hdr_t *) forwarding_packet;

  if (ip_hdr->ip_ttl <= 1) {
    /* Send ICMP time exceeded*/
    sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_time_exceeded, icmp_code_0, ip_packet);
    createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);

    free(icmp_t3_wrapper.packet);
  } else {
    /* Re-determine forwarding interfaces for packet after possible NAT translation */
    struct sr_rt* forward_rt = get_longest_prefix_match_interface(sr->routing_table, forwarding_ip_hdr->ip_dst);
    
    if (forward_rt == NULL) {
      /* Send ICMP network unreachable if the ip cannot be identified through our routing table */
      sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_0, ip_packet);
      createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);

      free(icmp_t3_wrapper.packet);
    } else {
      /* Check if the destination is in the arp cache */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), forwarding_ip_hdr->ip_dst);
      unsigned int ip_packet_len = ntohs(forwarding_ip_hdr->ip_len);

      /* Decrement the TTL */
      increment_ttl(forwarding_packet, -1);
  
      if (arp_entry == NULL) {
        /* Entry for ip_dst missing in cache table, queue the packet*/       
        queue_ethernet_packet(sr, forwarding_packet, ip_packet_len, eth_dest);
      } else {
        /* When forwarding to next-hop, only mac addresses change*/
        struct sr_if *forward_interface = sr_get_interface(sr, forward_rt->interface);
        eth_src = forward_interface->addr;
        eth_dest = arp_entry->mac;

        sr_create_send_ethernet_packet(sr, eth_src, eth_dest, ethertype_ip, forwarding_packet, ip_packet_len);
      }
      free(arp_entry);
    }
  }

  /* Free the NAT packet if it is in use */
  if (forwardNATPacket) {
    free(forwarding_packet);
  }
}

/*  Check for packet minimum length and checksum*/
int sr_ip_packet_is_valid(uint8_t *ip_packet, unsigned int ip_packet_len) {
  uint16_t checksum = cksum(ip_packet, IP_HDR_SIZE);

  int valid = ip_packet_len >= IP_HDR_SIZE && checksum == 0xffff;

  return valid;
}

int sr_is_packet_recipient(struct sr_instance *sr, uint32_t ip) {
  struct sr_if* if_walker = sr->if_list;

  while(if_walker)
  {
    if(if_walker->ip == ip) { 
      return 1; 
    }
    if_walker = if_walker->next;
  }
  return 0;
}

void queue_ethernet_packet(struct sr_instance *sr, uint8_t *ip_packet, unsigned int ip_packet_len, uint8_t* original_eth_shost) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  struct sr_rt* rt = get_longest_prefix_match_interface(sr->routing_table, ip_hdr->ip_dst);

  if (rt != NULL) {
    /* Holds the original ethernet address of sender in case of arp cache misses, resulting in sending
       back host unreachable*/
    uint8_t* placeholder_ether_shost = malloc(6);
    memcpy(placeholder_ether_shost, original_eth_shost, 6);
    sr_object_t ethernet_packet = create_ethernet_packet(placeholder_ether_shost, placeholder_ether_shost, ethertype_ip, ip_packet, ip_packet_len);
    free(placeholder_ether_shost);

    sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, ethernet_packet.packet, ethernet_packet.len, rt->interface);

    free(ethernet_packet.packet);
  }
}

/* Create an Ethernet packet and send it, len = size of data in bytes*/
void sr_create_send_ethernet_packet(struct sr_instance* sr, uint8_t* ether_shost, uint8_t* ether_dhost, uint16_t ethertype, uint8_t *data, uint16_t len) {
  char* outgoing_interface = get_interface_from_mac(ether_shost, sr);

  if (outgoing_interface != NULL) {
    sr_object_t ethernet_packet = create_ethernet_packet(ether_shost, ether_dhost, ethertype, data, len);

    sr_send_packet(sr, ethernet_packet.packet, ethernet_packet.len, outgoing_interface);

    free(ethernet_packet.packet);
  }
}

/* Should pass in correct ip*/
void createAndSendIPPacket(struct sr_instance* sr, uint32_t ip_src, uint32_t ip_dest, uint8_t* eth_src, uint8_t* eth_dest, uint8_t* ip_payload, uint8_t len) {
  /* Create ip packet by wrapping it over the payload*/
  sr_object_t ip_wrapper = create_ip_packet(ip_protocol_icmp,
      ip_src,
      ip_dest,
      ip_payload,
      len);

  /* Create ethernet packet by wrapping it over the ip packet*/
  sr_object_t eth_wrapper = create_ethernet_packet(eth_src,
      eth_dest,
      ethertype_ip,
      ip_wrapper.packet,
      ip_wrapper.len);

  char* outgoing_interface = get_interface_from_mac(eth_src, sr);

  if (outgoing_interface != NULL) {
    sr_send_packet(sr, eth_wrapper.packet, eth_wrapper.len, get_interface_from_mac(eth_src, sr));
  }

  free(ip_wrapper.packet);
  free(eth_wrapper.packet);
}


/* Copy the header from the Ethernet packet*/
sr_ethernet_hdr_t *sr_copy_ethernet_packet(uint8_t *ethernet_packet, unsigned int len) {
  /*unsigned int size = sizeof(struct sr_ethernet_hdr) + len;*/
  struct sr_ethernet_hdr* ethernet_hdr  = malloc(len);
  memcpy(ethernet_hdr, ethernet_packet, len);
  return ethernet_hdr;
}


/* Copy the header from the ARP packet*/
sr_arp_hdr_t *sr_copy_arp_hdr(uint8_t *ethernet_packet) {
  struct sr_arp_hdr* arp_hdr  = malloc(sizeof(struct sr_arp_hdr));
  memcpy(arp_hdr, ethernet_packet + ETHERNET_HDR_SIZE, sizeof(sr_arp_hdr_t));
  return arp_hdr;
}


/* Copy the IP packet from the Ethernet packet*/
uint8_t *sr_copy_ip_packet(uint8_t *ethernet_packet, unsigned int ip_packet_len) {
  uint8_t *ip_packet = malloc(ip_packet_len);
  memcpy(ip_packet, ethernet_packet + sizeof(sr_ethernet_hdr_t), ip_packet_len);
  return ip_packet;
}

/* Copy the ICMP header and data from the IP packet*/
uint8_t *sr_copy_icmp_packet(uint8_t *ip_packet, unsigned int ip_packet_len, unsigned int ip_hdr_len) {
  unsigned int icmp_packet_len = ip_packet_len - ip_hdr_len;

  uint8_t *icmp_packet = malloc(icmp_packet_len);
  memcpy(icmp_packet, ip_packet + ip_hdr_len, icmp_packet_len);
  return icmp_packet;
}

/* Copy the interface and initialize it in hardware order*/
struct sr_if *sr_copy_interface(struct sr_if *interface) {
  unsigned int size = sizeof(struct sr_if);
  struct sr_if *interface_copy = malloc(size);

  memcpy(interface_copy, interface, size);
  return interface_copy;
}

/* Helper function to determine if the router is the recipient of a packet while
   handling cases with NAT */
int sr_nat_is_packet_recipient(struct sr_instance *sr, struct sr_if *interface, uint8_t *ip_packet) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_packet;

  if (sr->nat.is_active) {
    uint16_t id = 0;
    sr_nat_mapping_type type;
    int isValidNATType = 1;
    int isUnsolicitedSyn = 0;

    if (ip_hdr->ip_p == ip_protocol_icmp) {
      sr_icmp_nat_hdr_t *icmp_hdr = (sr_icmp_nat_hdr_t *)(ip_packet + sizeof(sr_ip_hdr_t));
      id =  icmp_hdr->id;
      type = nat_mapping_icmp;
    } else if (ip_hdr->ip_p == ip_protocol_tcp) {
      sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_packet + sizeof(sr_ip_hdr_t));
      id =  tcp_hdr->port_dst;
      type = nat_mapping_tcp;
      isUnsolicitedSyn = tcp_hdr->syn && ip_hdr->ip_dst == sr->nat.external_if_ip;
    } else {
      isValidNATType = 0;
    }

    /* Packets from external sources to the router without a NAT mapping are determined to be
       for the router */
    if (isValidNATType && sr_is_interface_external(interface)) {
      struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat), id, type);

      if (mapping != NULL || isUnsolicitedSyn) {
        free(mapping);
        return 0;
      }
    }
  }

  return sr_is_packet_recipient(sr, ip_hdr->ip_dst);
}

void handle_unsolicited_syn(struct sr_instance* sr, uint8_t* packet){
  pthread_t syn_thread;
  pthread_attr_t syn_thread_attr;
  pthread_attr_init(&syn_thread_attr);
  pthread_attr_setdetachstate(&syn_thread_attr , PTHREAD_CREATE_DETACHED);

  struct thread_input* input = malloc(sizeof(struct thread_input));
  input->sr = sr;
  input->packet = packet;

  pthread_create(&syn_thread, &syn_thread_attr, unsolicited_syn_thread, (void*)input);
}

void *unsolicited_syn_thread(void* input) {
  struct thread_input* info = (struct thread_input*)input;
  
  struct sr_nat nat = info->sr->nat;
  struct sr_instance* sr = info->sr;
  uint8_t* packet = info->packet;
  struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*) packet;
  struct sr_tcp_hdr* tcp_hdr = (struct sr_tcp_hdr*) packet+sizeof(struct sr_ip_hdr);

  time_t curtime = time(NULL);
  sleep(6.0);
  
  int success = 0;

  pthread_mutex_lock(&(nat.tcp_lock));
  struct sr_nat_mapping* curr_map = nat.tcp_mappings;

  while (curr_map) {
    if(find_connection(curr_map, ip_hdr->ip_src, tcp_hdr->port_src) != NULL){
      /* Successful if there is a connection within 6 seconds */
      if(difftime(curr_map->time_created, curtime) <= 6.0){
        success = 1;
        break;
      }
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat.tcp_lock));

  /* Ports below 1024 are not allow for NAT and should send back a port unreachable */
  if (!success && ntohs(tcp_hdr->port_dst) >= 1024) {
    struct sr_rt* targetRT = get_longest_prefix_match_interface(sr->routing_table, ip_hdr->ip_src);

    if (targetRT != NULL) {
      struct sr_if *targetInterface = sr_get_interface(sr, targetRT->interface);

      sr_object_t icmpPacket = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_3, packet);
      sr_object_t IPPacket = create_ip_packet(ip_protocol_icmp, nat.external_if_ip, 
                                              ip_hdr->ip_src, icmpPacket.packet, icmpPacket.len);
      
      struct sr_if* source_interface = sr_get_interface(sr, externalInterface);

      sr_object_t sendEthernet = create_ethernet_packet( targetInterface->addr, (uint8_t*)source_interface->addr,
                                                                      ethertype_ip, IPPacket.packet, IPPacket.len);
                    
      sr_send_packet(sr, sendEthernet.packet, sendEthernet.len, targetInterface->name);

      free(icmpPacket.packet);
      free(IPPacket.packet);
      free(sendEthernet.packet);
      free(packet);
    }
  }
  return 0;
}

/* Handle outbound packets
     A) ICMP:
       1. Insert NAT mapping
       2. Modify Packet:
         1) Internal ICMP ID -> External ICMP ID
         2) Internal source IP -> External source IP
         3) Recompute checksum of ICMP header and IP header
     B) TCP:
       1. Insert NAT mapping
       2. Modify Packet:
         1) Internal TCP port -> External TCP port
         2) Internal source IP -> External source IP
         3) Recompute checksum of TCP and IP
         4) Update connection state based on tcp flags

    TODO: handle TCP connection state update */
int sr_nat_handle_internal(struct sr_instance *sr, uint8_t *ip_packet){
  struct sr_nat* nat = &(sr->nat);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  if(ip_hdr->ip_p == ip_protocol_udp) return 0;

  if(ip_hdr->ip_p == ip_protocol_icmp) {
    sr_icmp_nat_hdr_t *icmp_hdr = (sr_icmp_nat_hdr_t*)(ip_packet + sizeof(sr_ip_hdr_t));

    /* Only need to handle echo requests from internal addresses */
    if (icmp_hdr->icmp_type == icmp_type_echo_request && icmp_hdr->icmp_code == icmp_code_0) {
      struct sr_nat_mapping *icmp_mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src,
        icmp_hdr->id, nat_mapping_icmp);

      icmp_hdr->id = icmp_mapping->aux_ext;
      icmp_hdr->icmp_sum = htons(0);
      icmp_hdr->icmp_sum = cksum((uint8_t *) icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

      /* An internal->external packet will use the NAT's external ip as its source */
      ip_hdr->ip_src = icmp_mapping->ip_ext;
      ip_hdr->ip_sum = htons(0);
      ip_hdr->ip_sum = cksum((uint8_t *) ip_hdr, sizeof(sr_ip_hdr_t));

      free(icmp_mapping);
    }
  } else {
      sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(ip_packet + sizeof(sr_ip_hdr_t));

      if (ntohs(tcp_hdr->port_dst) < 1024) {
        return -1;
      }

      /* Initialize the tcp mapping and connections and apply it to the packet */
      struct sr_nat_mapping *mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src, tcp_hdr->port_src, nat_mapping_tcp);
      update_tcp_connection_internal(nat, ip_hdr, tcp_hdr);

      ip_hdr->ip_src = mapping->ip_ext;
      ip_hdr->ip_sum = htons(0);
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      /* Tcp must be calculated after ip changes as it depends on ip_src/dst */
      tcp_hdr->port_src = mapping->aux_ext;
      tcp_hdr->tcp_sum = htons(0);
      tcp_hdr->tcp_sum = tcp_cksum(ip_packet);

      free(mapping);
  }
  return 1;
}


/* Handle inbound packets
    A) ICMP:
      1. Check NAT mapping, if found:
        1) External ICMP ID -> Internal ICMP ID
        2) External source IP -> Internal source IP
        3) Recompute checksum of ICMP header and IP header
      2. If mapping not found:
        1) Drop it
    B) TCP:
      1. Check NAT mapping, if found:  
        1) External TCP port -> Internal TCP port
        2) External source IP -> Internal source IP
        3) Recompute checksum of TCP and IP
        4) Update connection state based on tcp flags 
      2. If mapping not found:
        1) Call handle_unsolicited_syn 

   TODO: handle TCP connection state update */
int sr_nat_handle_external(struct sr_instance *sr, uint8_t *ip_packet) {
  struct sr_nat* nat = &(sr->nat);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  if(ip_hdr->ip_p == ip_protocol_udp) return 0;

  if(ip_hdr->ip_p == ip_protocol_icmp){
    sr_icmp_nat_hdr_t *icmp_hdr = (sr_icmp_nat_hdr_t*)(ip_packet + sizeof(sr_ip_hdr_t));

    struct sr_nat_mapping *icmp_mapping = sr_nat_lookup_external(nat, icmp_hdr->id, nat_mapping_icmp);

    if (!icmp_mapping) return 0;

    icmp_hdr->id = icmp_mapping->aux_int;
    icmp_hdr->icmp_sum = htons(0);
    icmp_hdr->icmp_sum = cksum((uint8_t *) icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

    /* An external->internal packet will need its destination ip re-translated */
    ip_hdr->ip_dst = icmp_mapping->ip_int;
    ip_hdr->ip_sum = htons(0);
    ip_hdr->ip_sum = cksum((uint8_t *) ip_hdr, sizeof(sr_ip_hdr_t));

    free(icmp_mapping);
  } else {
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(ip_packet + sizeof(sr_ip_hdr_t));

    if (ntohs(tcp_hdr->port_dst) < 1024) {
      return -1;
    }

    /* Lookup for TCP packet */
    struct sr_nat_mapping *tcp_mapping = sr_nat_lookup_external(nat, tcp_hdr->port_dst, nat_mapping_tcp);

    if (tcp_mapping) {
      update_tcp_connection_external(nat, ip_hdr, tcp_hdr);

      ip_hdr->ip_dst = tcp_mapping->ip_int;
      ip_hdr->ip_sum = htons(0);
      ip_hdr->ip_sum = cksum((uint8_t *) ip_hdr, sizeof(sr_ip_hdr_t));
      
      /* Tcp must be calculated after ip changes as it depends on ip_src/dst */
      tcp_hdr->port_dst = tcp_mapping->aux_int;
      tcp_hdr->tcp_sum = htons(0);
      tcp_hdr->tcp_sum = tcp_cksum(ip_packet);

      free(tcp_mapping);
    } else {
      if (tcp_hdr->syn) {
        uint8_t *copy = malloc(ip_hdr->ip_len);
        memcpy(copy, ip_packet, ip_hdr->ip_len);

        handle_unsolicited_syn(sr, copy);
      }
      return 0;
    }
  }
  return 1;
}
