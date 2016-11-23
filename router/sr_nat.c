
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat, uint32_t icmp_query_timeout,
uint32_t tcp_established_idle_timeout,uint32_t tcp_transitory_idle_timeout){ /* Initializes the nat */

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

void deleteConnections(struct sr_nat_connection* connections){
  struct sr_nat_connection* temp;
  while(connections)
    temp = connections->next;
    free(connections);
    connections = temp;
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
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    struct sr_nat_mapping* curr_map = nat->mappings;
    while(curr_map){
      if(curr_map->type == nat_mapping_icmp){
        if(difftime(curtime, curr_map->last_updated) >= nat->icmp_query_timeout){
          timeout_mapping(nat, curr_map);
        }
      }
      else{/*timeout tcp connections*/
        struct sr_nat_connection* curr_conn = curr_map->conns;
        while(curr_conn){
          if(tcp_connection_expired(nat, curr_conn)){
            timeout_tcp_connections(curr_conn, curr_map);
          }
          curr_conn = curr_conn->next;
        }
        if(!curr_map->conns){
          timeout_mapping(nat, curr_map);
        }
      }
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/*deletes mapping from the nat*/
void timeout_mapping(struct sr_nat* nat, struct sr_nat_mapping* map){
  if (nat->mappings == map){
    nat->mappings = map->next;
    free(map);
  }
  else{
    struct sr_nat_mapping* curr_map = nat->mappings->next;
    struct sr_nat_mapping* prev_map = nat->mappings;
    while(curr_map){
      if(curr_map == map){/* delete*/
        prev_map->next = curr_map->next;
        free(curr_map);
        break;      
      }
      else{/* move on to next map*/
        curr_map = curr_map->next;
        prev_map = prev_map->next;
      }
    }
  }
}
/*1 if tcp connection expired, 0 otherwise*/
int  tcp_connection_expired(struct sr_nat* nat, struct sr_nat_connection* connection){
  time_t curtime = time(NULL);
  if(connection->current_state == tcp_established && 
    difftime(curtime,connection->last_updated) >= nat->tcp_established_idle_timeout){
    return 1;
  }
  else if(connection->current_state == tcp_transitory && 
    difftime(curtime,connection->last_updated) >= nat->tcp_transitory_idle_timeout){
    return 1;
  }
  return 0;
}
/*deletes tcp connections*/
void timeout_tcp_connections(struct sr_nat_connection* conn, struct sr_nat_mapping* map){
  if (map->conns == conn){
    map->conns = conn->next;
    free(conn);
  }
  else{
    struct sr_nat_connection* curr_conn = map->conns->next;
    struct sr_nat_connection* prev_conn = map->conns;
    while(curr_conn){
      if(curr_conn == conn){/* delete*/
        prev_conn->next = curr_conn->next;
        free(conn);
        break;      
      }
      else{/* move on to next connection*/
        curr_conn = curr_conn->next;
        prev_conn = prev_conn->next;
      }
    }
  }
}


/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = sr_nat_lookup_external_nolock(nat,
    aux_ext, type);

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* This function implements the lookup_external function without lock,
   this implementation is separated from locks to prevent dead lock when
   called somewhere else, this function should only be called with lock 
   acquired. */
struct sr_nat_mapping *sr_nat_lookup_external_nolock(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *map_walker = nat->mappings;

  while(map_walker){
    if(map_walker->type == type && map_walker->aux_ext == aux_ext){

      /*fprintf(stderr, "Found external mapping match\n")*/
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, map_walker, sizeof(struct sr_nat_mapping));
      break;
    }
    map_walker = map_walker->next;
  }

  return copy;
}


/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = sr_nat_lookup_internal_nolock(nat,
    ip_int, aux_int, type);

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* This function implements the lookup_internal function without lock,
   this implementation is separated from locks to prevent dead lock when
   called somewhere else, this function should only be called with lock 
   acquired. */
struct sr_nat_mapping *sr_nat_lookup_internal_nolock(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *map_walker = nat->mappings;

  while(map_walker){
    if(map_walker->type == type && map_walker->aux_int == aux_int &&
      map_walker->ip_int == ip_int){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, map_walker, sizeof(struct sr_nat_mapping));
      break;
    }
    map_walker = map_walker->next;
  }
  return copy;
}


/* Insert a new mapping into the nat's mapping table if it does not exist.
   Actually returns a copy to the new mapping, for thread safety. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));

  /* Can't just call sr_nat_lookup_internal here, will cause deadlock */
  struct sr_nat_mapping *internal_mapping = sr_nat_lookup_internal_nolock(
    nat, ip_int, aux_int, type);

  /* If the mapping does not exists, create the mapping */
  if (internal_mapping == NULL) {
    internal_mapping = sr_nat_create_mapping(nat, ip_int, aux_int, type);
    internal_mapping->next = nat->mappings;
    nat->mappings = internal_mapping;
  }

  /* Create a copy of the mapping */
  memcpy(copy, internal_mapping, sizeof(struct sr_nat_mapping));
  free(internal_mapping);

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
    start_aux = START_PORT;
    end_aux = END_PORT;
  } else {
    aux_ext_mapping = nat->icmp_id_mapping;
    start_aux = START_ID;
    end_aux = END_ID;
  }

  /* Search through the unique mapping */
  struct sr_aux_ext_mapping *map_walker = aux_ext_mapping->mappings;

  while (map_walker) {
    if(map_walker->ip_int == ip_int && map_walker->aux_int == aux_int) {
      return map_walker->aux_ext;
    }
    map_walker = map_walker->next;
  }

  /* If no mapping found, create mapping and assign the current available port/id */
  struct sr_aux_ext_mapping *new_mapping = malloc(sizeof(struct sr_aux_ext_mapping));
  new_mapping->ip_int = ip_int;
  new_mapping->aux_int = aux_int;
  new_mapping->aux_ext = aux_ext_mapping->current_aux;
  new_mapping->next = aux_ext_mapping->mappings;

  /* Update the mapping */
  aux_ext_mapping->mappings = new_mapping;
  aux_ext_mapping->current_aux += 1;

  /* Rollover the auxiliary Id if it exceeds the limit */
  if (aux_ext_mapping->current_aux > end_aux) {
    aux_ext_mapping->current_aux = start_aux;
  }

  return new_mapping->aux_ext;
}


int sr_nat_handle_internal(struct sr_nat *nat, struct sr_ethernet_hdr *ethernet_hdr, uint8_t *ip_packet){
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  if(ip_hdr->ip_p == ip_protocol_udp) return 0;

  if(ip_hdr->ip_p == ip_protocol_icmp){
    sr_icmp_nat_hdr_t *icmp_hdr = (sr_icmp_nat_hdr_t*)(ip_packet + sizeof(sr_ip_hdr_t));

    /* Only need to handle echo requests from internal addresses */
    if (icmp_hdr->icmp_type == icmp_type_echo_request && icmp_hdr->icmp_code == icmp_code_0) {
      struct sr_nat_mapping *icmp_mapping = icmp_mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src,
        icmp_hdr->id, nat_mapping_icmp);

      icmp_hdr->id = icmp_mapping->aux_ext;

      ip_hdr->ip_src = icmp_mapping->ip_ext;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      free(icmp_mapping);
    }
  } else {
      sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(ip_hdr + sizeof(sr_ip_hdr_t));

      /* Initialize the tcp mapping and connections and apply it to the packet */
      struct sr_nat_mapping *mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src, tcp_hdr->port_src, nat_mapping_tcp);
      create_and_insert_nat_connection(mapping, ip_hdr->ip_dst, tcp_hdr->port_dst, mapping->ip_ext, mapping->aux_ext);

      /* Recalculate checksums */
      tcp_hdr->port_src = mapping->aux_ext;
      tcp_hdr->tcp_sum = 0;
      tcp_hdr->tcp_sum = tcp_cksum(ip_packet);

      ip_hdr->ip_src = mapping->ip_ext;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      free(mapping);
  }
  return 1;
}

struct sr_nat_connection* create_and_insert_nat_connection(struct sr_nat_mapping *map, uint32_t ip_ext, 
  uint16_t aux_ext, uint32_t ip_remote, uint16_t aux_remote){
  
  struct sr_nat_connection *output = find_connection(map, ip_remote, aux_remote);

  if (!output) {
    output = malloc(sizeof(struct sr_nat_connection));
    output->ip_ext = ip_ext;
    output->aux_ext = aux_ext;
    output->ip_remote = ip_remote;
    output->aux_remote = aux_remote; 
    output->last_updated = time(NULL); 
    output->next = map->conns;
    map->conns = output;
  } else {
    /*update the current connection's last_updated field*/
    output->last_updated = time(NULL); 
  }

  return output;
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