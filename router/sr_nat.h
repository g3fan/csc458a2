
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define sr_IFACE_NAMELEN 32
#define START_PORT 1025
#define END_PORT 65535
#define START_ID 0
#define END_ID 65535

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum{
  tcp_established,
  tcp_transitory
} tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_ext;
  uint16_t aux_ext;
  uint32_t ip_remote;
  uint16_t aux_remote; 
  time_t last_updated; 
  tcp_state current_state;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t time_created;
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_aux_ext_mapping_wrap {
  uint16_t current_aux;
  struct sr_aux_ext_mapping *mappings;
};

struct sr_aux_ext_mapping {
  uint32_t ip_int; /* internal ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  struct sr_aux_ext_mapping *next;
};

struct sr_nat {
  int is_active;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;

  /* add any fields here */
  struct sr_nat_mapping *mappings;

  uint32_t icmp_query_timeout;
  uint32_t tcp_established_idle_timeout;
  uint32_t tcp_transitory_idle_timeout;

  /* constant interface IP */
  uint32_t external_if_ip;
  uint32_t internal_if_ip;

  /* unique mapping of (internal IP + aux_int) to aux_ext */
  struct sr_aux_ext_mapping_wrap *tcp_port_mapping;
  struct sr_aux_ext_mapping_wrap *icmp_id_mapping;
};

int   sr_nat_init(struct sr_nat *nat, uint32_t icmp_query_timeout,
uint32_t tcp_established_idle_timeout,uint32_t tcp_transitory_idle_timeout);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* deletes connections from a nat connection struct*/
void timeout_mapping(struct sr_nat* nat, struct sr_nat_mapping* map);

/* check if tcp connectino expired*/
int  tcp_connection_expired(struct sr_nat* nat, struct sr_nat_connection* connection);

/*delete tcp connection from mapping*/
void timeout_tcp_connections(struct sr_nat_connection* conn, struct sr_nat_mapping* map);

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/*added*/
struct sr_nat_mapping *sr_nat_create_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

struct sr_nat_mapping *sr_nat_lookup_external_nolock(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type );

struct sr_nat_mapping *sr_nat_lookup_internal_nolock(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

uint16_t get_unique_aux_ext(struct sr_nat *nat, uint32_t ip_int, 
  uint16_t aux_int, sr_nat_mapping_type type);

struct sr_nat_connection* create_and_insert_nat_connection(struct sr_nat_mapping *map, uint32_t ip_ext, 
  uint16_t aux_ext, uint32_t ip_remote, uint16_t aux_remote);

struct sr_nat_connection* find_connection(struct sr_nat_mapping *map, 
  uint32_t ip_remote, uint16_t aux_remote);

uint32_t get_nat_ip_src(struct sr_nat *nat, uint8_t *ip_packet);
#endif