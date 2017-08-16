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

struct probe_metric_s dawn_metric;

struct probe_metric_s {
    int ht_support;
    int vht_support;
    int n_ht_support;
    int n_vht_support;
    int rssi;
    int freq;
};

#define SORT_NUM 5
#define TIME_THRESHOLD 30  // every minute

// Probe entrys
typedef struct probe_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t target_addr[ETH_ALEN];
    uint32_t signal;
    uint32_t freq;
    //uint8_t ht_support;
    //uint8_t vht_support;
    time_t time;
    int counter;
} probe_entry;

typedef struct {
    uint32_t freq;
} client_request;

typedef struct client_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t ht_supported;
    uint8_t vht_supported;
    uint32_t freq;
    uint8_t auth;
    uint8_t assoc;
    uint8_t authorized;
    uint8_t preauth;
    uint8_t wds;
    uint8_t wmm;
    uint8_t ht;
    uint8_t vht;
    uint8_t wps;
    uint8_t mfp;
    time_t time;
    uint32_t aid;
} client;


// Array
#define ARRAY_CLIENT_LEN 1000
#define TIME_THRESHOLD_CLIENT 30
#define TIME_THRESHOLD_CLIENT_UPDATE 10
#define TIME_THRESHOLD_CLIENT_KICK 60


struct client_s client_array[ARRAY_CLIENT_LEN];
pthread_mutex_t client_array_mutex;

void insert_client_to_array(client entry);

void kick_clients(uint8_t bssid[], uint32_t id);

void client_array_insert(client entry);

client *client_array_delete(client entry);

void print_client_array();

void print_client_entry(client entry);

void *remove_client_array_thread(void *arg);

#define ARRAY_LEN 1000

struct probe_entry_s probe_array[ARRAY_LEN];
pthread_mutex_t probe_array_mutex;

probe_entry insert_to_array(probe_entry entry, int inc_counter);

void probe_array_insert(probe_entry entry);

probe_entry probe_array_delete(probe_entry entry);

void print_array();

void *remove_array_thread(void *arg);


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