#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

#define IS_URG(flags) ((flags) & (tcp_flag_urg))
#define IS_ACK(flags) ((flags) & (tcp_flag_ack))
#define IS_PSH(flags) ((flags) & (tcp_flag_psh))
#define IS_RST(flags) ((flags) & (tcp_flag_rst))
#define IS_SYN(flags) ((flags) & (tcp_flag_syn))
#define IS_FIN(flags) ((flags) & (tcp_flag_fin))

int sr_nat_init(struct sr_nat *nat, uint32_t icmp_query_timeout,
  uint32_t tcp_established_idle_timeout,uint32_t tcp_transitory_idle_timeout) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->is_active = 1;
  nat->mappings = NULL;

  /* Initialize any variables here */
  nat->icmp_query_timeout = icmp_query_timeout;
  nat->tcp_established_idle_timeout = tcp_established_idle_timeout;
  nat->tcp_transitory_idle_timeout = tcp_transitory_idle_timeout;

  nat->tcp_port_mapping = malloc(sizeof(struct sr_aux_ext_mapping_wrap));
  nat->tcp_port_mapping->current_aux = htons(START_PORT);
  nat->tcp_port_mapping->mappings = NULL;

  nat->icmp_id_mapping = malloc(sizeof(struct sr_aux_ext_mapping_wrap));
  nat->icmp_id_mapping->current_aux = htons(START_ID);
  nat->icmp_id_mapping->mappings = NULL;

  return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;

  struct sr_nat_connection* curr_conn;
  struct sr_nat_mapping* curr_map;
  time_t curtime;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    curtime = time(NULL);

    curr_map = nat->mappings;
    while(curr_map){
      if(curr_map->type == nat_mapping_icmp){
        if(difftime(curtime, curr_map->last_updated) >= nat->icmp_query_timeout){
          curr_map->marked_for_delete = 1;
        }
      }
      else{/*timeout tcp connections*/
        curr_conn = curr_map->conns;
        while(curr_conn){
          if(tcp_connection_expired(nat, curr_conn)){
            curr_conn->marked_for_delete = 1;
          }
          curr_conn = curr_conn->next;
        }
        timeout_tcp_connections(curr_map);
        if(!curr_map->conns){
          curr_map->marked_for_delete = 1;
        }
      }
      curr_map = curr_map->next;
    }

    timeout_mapping(nat);
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/*deletes mapping from the nat*/
void timeout_mapping(struct sr_nat* nat){
  struct sr_nat_mapping* curr_map = nat->mappings;
  struct sr_nat_mapping* prev_map = NULL;
  struct sr_nat_mapping* delete_this_map = NULL;
  while(curr_map){
    if(curr_map->marked_for_delete){
      delete_this_map = curr_map;
      if(!prev_map){/*we are deleting the head*/
        nat->mappings = curr_map->next;
        curr_map = curr_map->next;
      }
      else{
        curr_map = curr_map->next;
        prev_map->next = curr_map;
      }
      free(delete_this_map);
    }
    else{
      prev_map = curr_map;
      curr_map = curr_map->next;
    }
  }
}

/*1 if tcp connection expired, 0 otherwise*/
int  tcp_connection_expired(struct sr_nat* nat, struct sr_nat_connection* connection){
  time_t curtime = time(NULL);
  if(connection->state == tcp_established && 
    difftime(curtime,connection->last_updated) >= nat->tcp_established_idle_timeout){
    return 1;
  }
  else if(connection->state == tcp_transitory && 
    difftime(curtime,connection->last_updated) >= nat->tcp_transitory_idle_timeout){
    return 1;
  }
  return 0;
}

/*deletes tcp connections*/
void timeout_tcp_connections(struct sr_nat_mapping* map){

  struct sr_nat_connection* curr_conn = map->conns;
  struct sr_nat_connection* prev_conn = NULL;
  struct sr_nat_connection* delete_this_conn = NULL;
  while(curr_conn){
    if(curr_conn->marked_for_delete){
      delete_this_conn = curr_conn;
      if(!prev_conn){
        map->conns = curr_conn->next;
        curr_conn = curr_conn->next;
      }
      else{
        curr_conn = curr_conn->next;
        prev_conn->next = curr_conn;
      }
      free(delete_this_conn);
    }
    else{
      prev_conn = curr_conn;
      curr_conn = curr_conn->next;
    }
  }
}


/* Get the mapping associated with given external guid.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping_ptr = sr_nat_lookup_external_ptr(nat,
    aux_ext, type);

  /* If the mapping is found, make a copy of the mapping */
  if (mapping_ptr) {
    copy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping_ptr, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* This function implements the lookup_external function without lock,
   this implementation is separated from locks to prevent dead lock when
   called somewhere else, this function should only be called with lock 
   acquired. */
struct sr_nat_mapping *sr_nat_lookup_external_ptr(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  struct sr_nat_mapping *map_walker = nat->mappings;

  while(map_walker){
    if(map_walker->type == type && map_walker->aux_ext == aux_ext){
      break;
    }
    map_walker = map_walker->next;
  }
  return map_walker;
}


/* Get the mapping associated with given internal (ip, port/id) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping_ptr = sr_nat_lookup_internal_ptr(nat,
    ip_int, aux_int, type);

  /* If the mapping is found, make a copy of the mapping */
  if (mapping_ptr) {
    copy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping_ptr, sizeof(struct sr_nat_mapping));
  }
  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* This function implements the lookup_internal function without lock,
   this implementation is separated from locks to prevent dead lock when
   called somewhere else, this function should only be called with lock 
   acquired. 

   This function returns a pointer to the nat mapping, remember to create a copy of it.
   If no mapping is found, return NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal_ptr(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  struct sr_nat_mapping *map_walker = nat->mappings;

  while(map_walker){
    if(map_walker->type == type && map_walker->aux_int == aux_int &&
      map_walker->ip_int == ip_int){
      break;
    }
    map_walker = map_walker->next;
  }
  return map_walker;
}


/* Insert a new mapping into the nat's mapping table if it does not exist.
   Actually returns a copy to the new mapping, for thread safety. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));

  /* Can't just call sr_nat_lookup_internal here, will cause deadlock */
  struct sr_nat_mapping *mapping_ptr = sr_nat_lookup_internal_ptr(nat, ip_int, aux_int, type);

  /* If the mapping does not exists, create the mapping */
  if (mapping_ptr == NULL) {
    mapping_ptr = sr_nat_create_mapping(nat, ip_int, aux_int, type);
    mapping_ptr->next = nat->mappings;
    nat->mappings = mapping_ptr;
  }

  /* Create a copy of the mapping */
  memcpy(copy, mapping_ptr, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* Create a NAT mapping.
   Should only be called with lock acquired, because it may modify the unique aux_ext mapping. */
struct sr_nat_mapping *sr_nat_create_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ){

  struct sr_nat_mapping *newmap = malloc(sizeof(struct sr_nat_mapping));
  newmap->type = type;
  newmap->ip_int = ip_int; 
  newmap->ip_ext = nat->external_if_ip;
  newmap->aux_int = aux_int; 
  newmap->aux_ext = get_unique_aux_ext(nat, ip_int, aux_int, type);
  newmap->last_updated = time(NULL);
  newmap->conns = NULL;
  newmap->next = NULL;
  newmap->marked_for_delete = 0;
  return newmap;
}


/* Should only be called with lock acquired.

   Need to be "endpoint independent", which means:
   unique(internal IP + internal port) -> unique(external port)
   unique(internal IP + internal sequence ID) -> unique( external sequence ID) */
uint16_t get_unique_aux_ext(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type){

  /* Get the mapping based on type */
  struct sr_aux_ext_mapping_wrap *aux_ext_mapping = NULL;
  uint16_t end_aux;
  uint16_t start_aux;

  if (type == nat_mapping_tcp) {
    aux_ext_mapping = nat->tcp_port_mapping;
    start_aux = htons(START_PORT);
    end_aux = htons(END_PORT);
  } else {
    aux_ext_mapping = nat->icmp_id_mapping;
    start_aux = htons(START_ID);
    end_aux = htons(END_ID);
  }

  /* Search through the unique mapping */
  struct sr_aux_ext_mapping *map_walker = aux_ext_mapping->mappings;

  while (map_walker) {
    if(map_walker->ip_int == ip_int && map_walker->aux_int == aux_int) {
      return map_walker->aux_ext;
    }
    map_walker = map_walker->next;
  }

  /* TODO: Determine if the extra lists are needed  */
  /* If no mapping found, create mapping and assign the current available port/id */
  struct sr_aux_ext_mapping *new_mapping = malloc(sizeof(struct sr_aux_ext_mapping));
  new_mapping->ip_int = ip_int;
  new_mapping->aux_int = aux_int;
  new_mapping->aux_ext = aux_ext_mapping->current_aux;
  new_mapping->next = aux_ext_mapping->mappings;

  /* Update the mapping */
  aux_ext_mapping->mappings = new_mapping;
  aux_ext_mapping->current_aux = htons(ntohs(aux_ext_mapping->current_aux) + 1);

  /* Rollover the auxiliary Id if it exceeds the limit */
  if (ntohs(aux_ext_mapping->current_aux) > ntohs(end_aux)) {
    aux_ext_mapping->current_aux = start_aux;
  }

  return new_mapping->aux_ext;
}


void update_tcp_connection_internal(struct sr_nat *nat, sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr) {

  pthread_mutex_lock(&(nat->lock));

  uint32_t ip_int = ip_hdr->ip_src;
  uint16_t aux_int = tcp_hdr->port_src;

  struct sr_nat_mapping *mapping_ptr = sr_nat_lookup_internal_ptr(nat, ip_int, aux_int, nat_mapping_tcp);

  if (mapping_ptr) {
    update_tcp_connection(mapping_ptr, ip_hdr, tcp_hdr);
  }

  pthread_mutex_unlock(&(nat->lock));
}

void update_tcp_connection_external(struct sr_nat *nat, sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr) {

  pthread_mutex_lock(&(nat->lock));

  uint16_t aux_ext = tcp_hdr->port_dst;

  struct sr_nat_mapping *mapping_ptr = sr_nat_lookup_external_ptr(nat, aux_ext, nat_mapping_tcp);

  if (mapping_ptr) {
    update_tcp_connection(mapping_ptr, ip_hdr, tcp_hdr);
  }

  pthread_mutex_unlock(&(nat->lock));
}


void update_tcp_connection(struct sr_nat_mapping *mapping, sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr) {
  uint32_t ip_ext = mapping->ip_ext;
  uint16_t aux_ext = mapping->aux_ext;;
  uint32_t ip_remote = ip_hdr->ip_dst;
  uint16_t aux_remote = tcp_hdr->port_src;
  uint8_t flags = get_tcp_flags(tcp_hdr);

  struct sr_nat_connection *connection_ptr = lookup_tcp_connection_ptr(mapping, ip_remote, aux_remote, ip_ext, aux_ext);

  if (connection_ptr) {
    update_tcp_connection_state(connection_ptr, flags);
  } else {
    /* If no connection exists, create one */
    connection_ptr = create_tcp_connection(ip_ext, ip_remote, aux_ext, aux_remote, flags);
    connection_ptr->next = mapping->conns;
    mapping->conns = connection_ptr;
  }
}


struct sr_nat_connection* lookup_tcp_connection_ptr(struct sr_nat_mapping *map, uint32_t ip_remote, uint16_t aux_remote,
  uint32_t ip_ext, uint16_t aux_ext) {

  struct sr_nat_connection *conns_walker = map->conns;

  while (conns_walker) {
    if(conns_walker->ip_remote == ip_remote && conns_walker->aux_remote == aux_remote &&
      conns_walker->ip_ext == ip_ext && conns_walker->aux_ext == aux_ext){
      return conns_walker;
    }
    conns_walker = conns_walker->next;
  }

  return NULL;
}


void update_tcp_connection_state(struct sr_nat_connection *connection, uint8_t curr_flags) {

  tcp_state state = connection->state;
  uint8_t last_flags = connection->last_flags;

  if (state == tcp_transitory) {
    if ((IS_SYN(last_flags) && IS_ACK(last_flags) && IS_ACK(curr_flags)) ||
      (IS_SYN(last_flags) && IS_ACK(last_flags) && IS_SYN(curr_flags) && IS_ACK(curr_flags))) {
      connection->state = tcp_established;
    }
  } else {
    if (IS_ACK(last_flags) && IS_FIN(curr_flags)) {
      connection->state = tcp_transitory;
    }
  }
}


struct sr_nat_connection* create_tcp_connection(uint32_t ip_ext, uint32_t ip_remote, uint16_t aux_ext, 
  uint16_t aux_remote, uint8_t flags) {

  struct sr_nat_connection *connection = malloc(sizeof(struct sr_nat_connection));

  connection->ip_ext = ip_ext;
  connection->ip_remote = ip_remote;
  connection->aux_ext = aux_ext;
  connection->aux_remote = aux_remote;
  connection->last_updated = time(NULL);
  connection->last_flags = 0;
  connection->state = tcp_transitory;
  connection->marked_for_delete = 0;
  connection->next = NULL;

  return connection;
}


uint8_t get_tcp_flags(sr_tcp_hdr_t *tcp_hdr) {
  uint8_t flags = 0;
  if (tcp_hdr->urg) flags = flags | tcp_flag_urg;
  if (tcp_hdr->ack) flags = flags | tcp_flag_ack;
  if (tcp_hdr->psh) flags = flags | tcp_flag_psh;
  if (tcp_hdr->rst) flags = flags | tcp_flag_rst;
  if (tcp_hdr->syn) flags = flags | tcp_flag_syn;
  if (tcp_hdr->fin) flags = flags | tcp_flag_fin;

  return flags;
}


struct sr_nat_connection* find_connection(struct sr_nat_mapping *map, uint32_t ip_remote, uint16_t aux_remote) {
  struct sr_nat_connection *conns_walker = map->conns;

  while (conns_walker) {
    if(conns_walker->ip_remote == ip_remote && conns_walker->aux_remote == aux_remote){
      return conns_walker;
    }
    conns_walker = conns_walker->next;
  }

  return NULL;
}


/* Returns the original source ip of a tcp or icmp packet */
uint32_t get_nat_ip_src(struct sr_nat *nat, uint8_t *ip_packet) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_packet;

  if (!nat->is_active) {
    return ip_hdr->ip_src;
  }

  struct sr_nat_mapping *mapping;
  uint32_t nat_ip_src = ip_hdr->ip_src;
  uint16_t aux_ext;
  sr_nat_mapping_type type;

  if (ip_hdr->ip_p == ip_protocol_tcp) {
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
    aux_ext = tcp_hdr->port_src;
    type = nat_mapping_tcp;
  } else {
    sr_icmp_nat_hdr_t *icmp_hdr = (sr_icmp_nat_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
    aux_ext = icmp_hdr->id;
    type = nat_mapping_icmp;
  }

  /* Check if we have an existing mapping based on the  */
  if (ip_hdr->ip_src == nat->external_if_ip) {
    mapping = sr_nat_lookup_external(nat, aux_ext, type);

    if (mapping != NULL) {
      nat_ip_src = mapping->ip_int;
    }
  } else {
    mapping = sr_nat_lookup_internal(nat, ip_hdr->ip_src, aux_ext, type);

    if (mapping != NULL) {
      nat_ip_src = mapping->ip_ext;
    }
  }

  return nat_ip_src;
}
