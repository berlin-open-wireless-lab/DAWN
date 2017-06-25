#ifndef __DAWN_DATASTORAGE_H
#define __DAWN_DATASTORAGE_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define SORT_NUM 5
#define TIME_THRESHOLD 60  // every minute

// Probe entrys
typedef struct {
  uint8_t bssid_addr[ETH_ALEN];
  uint8_t client_addr[ETH_ALEN];
  uint8_t target_addr[ETH_ALEN];
  uint32_t signal;
  uint32_t freq;
  time_t time;
  int counter;
} probe_entry;

// List
typedef struct node {
  probe_entry data;
  struct node *ptr;
} node;

node *insert(node *head, probe_entry entry);
void free_list(node *head);
void print_list();
void insert_to_list(probe_entry entry, int inc_counter);
int mac_first_in_probe_list(uint8_t bssid_addr[], uint8_t client_addr[]);

void *remove_thread(void *arg);

pthread_mutex_t list_mutex;
node *probe_list_head;
char sort_string[SORT_NUM];

#endif