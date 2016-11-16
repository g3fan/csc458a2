
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

  nat->mappings = NULL;
  /* Initialize any variables here */

  nat->icmp_query_timeout = icmp_query_timeout;
  nat->tcp_established_idle_timeout = tcp_established_idle_timeout;
  nat->tcp_transitory_idle_timeout = tcp_transitory_idle_timeout;

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
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
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

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *map_walker = nat->mappings;
  while(map_walker){
    if(map_walker->type == type && map_walker->aux_int == aux_int &&
      map_walker->ip_int == ip_int){
      /*fprintf(stderr, "Found interal mapping match\n")*/
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, map_walker, sizeof(struct sr_nat_mapping));
      break;
    }
    map_walker = map_walker->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_mapping *check_internal_map_exists = sr_nat_lookup_internal(nat,
    ip_int, aux_int, type);
  if (check_internal_map_exists != NULL) {
    memcpy(mapping, check_internal_map_exists, sizeof(struct sr_nat_mapping));
  }
  else{
    struct sr_nat_mapping *newmap = create_nat_mapping(nat,
      ip_int, aux_int, type);
    newmap->next = nat->mappings;
    nat->mappings = newmap;
    memcpy(mapping, newmap, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

struct sr_nat_mapping* create_nat_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ){
    struct sr_nat_mapping *newmap = malloc(sizeof(struct sr_nat_mapping));
    newmap->type = type;
    newmap->ip_int = ip_int; 
    newmap->ip_ext = nat->external_if_ip;
    newmap->aux_int = aux_int; 
    newmap->aux_ext = getFreePort(nat);
    newmap->last_updated = time(NULL);
    newmap->conns = NULL;
    newmap->next = NULL;
    return newmap;
}

uint16_t getFreePort(struct sr_nat *nat){
  if (nat->currentPort >= END_PORT) {
    nat->currentPort = START_PORT;
  } else {
    nat->currentPort++;
  }

  return nat->currentPort;
}

int nat_handle_interal_ip(struct sr_nat *nat, struct sr_ethernet_hdr *ethernet_hdr, uint8_t *ip_packet){
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;
  uint16_t source_port = *(uint16_t*)(ip_packet + sizeof(sr_ip_hdr_t));
  uint16_t dest_port = *(uint16_t*)(ip_packet + sizeof(sr_ip_hdr_t) + 2);

    /*add logic to drop UDP packets*/
  if(ip_hdr->ip_p == ip_protocol_udp) return 0;

  struct sr_nat_mapping *map = sr_nat_lookup_internal(nat, ip_hdr->ip_src, source_port, nat_mapping_tcp);
  if(!map){
    map = sr_nat_insert_mapping(nat, ip_hdr->ip_src, source_port, nat_mapping_tcp);
  }
  create_and_insert_nat_connection(map, ip_hdr->ip_dst, dest_port, map->ip_ext, map->aux_ext);
  ip_hdr->ip_src = map->ip_ext;
  memcpy(ip_packet + sizeof(sr_ip_hdr_t), &(map->aux_ext), sizeof(uint16_t));/*set tcp source port to mapping*/

  free(map);

  return 1;
}

struct sr_nat_connection* create_and_insert_nat_connection(struct sr_nat_mapping *map, uint32_t ip_ext, 
  uint16_t aux_ext, uint32_t ip_remote, uint16_t aux_remote){
  
  struct sr_nat_connection *output = find_connection(map, ip_remote, aux_remote);
  if(!output){
    output = malloc(sizeof(struct sr_nat_connection));
    output->ip_ext = ip_ext;
    output->aux_ext = aux_ext;
    output->ip_remote = ip_remote;
    output->aux_remote = aux_remote; 
    output->last_updated = time(NULL); 
    output->next = map->conns;
    map->conns = output;
  }
  return output;
}

struct sr_nat_connection* find_connection(struct sr_nat_mapping *map, 
  uint32_t ip_remote, uint16_t aux_remote){
  struct sr_nat_connection *conns_walker = map->conns;
  while(conns_walker){

    if(conns_walker->ip_remote == ip_remote && conns_walker->aux_remote == aux_remote){
      return conns_walker;
    }
    conns_walker = conns_walker->next;
  }
  return NULL;
}