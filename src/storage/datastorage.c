#include "datastorage.h"

#include "ubus.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int go_next_help(char sort_order[], int i, probe_entry entry,
                 probe_entry next_entry);
int go_next(char sort_order[], int i, probe_entry entry,
            probe_entry next_entry);
int mac_is_equal(uint8_t addr1[], uint8_t addr2[]);
int mac_is_greater(uint8_t addr1[], uint8_t addr2[]);
void print_probe_entry(probe_entry entry);
void remove_old_probe_entries(time_t current_time, long long int threshold);

int client_array_go_next(char sort_order[], int i, client entry,
            client next_entry);
int client_array_go_next_help(char sort_order[], int i, client entry,
                 client next_entry);
void remove_old_client_entries(time_t current_time, long long int threshold);
int kick_client(uint8_t bssid[], uint8_t client[]);

int probe_entry_last = -1;
int client_entry_last = -1;

int kick_client(uint8_t bssid[], uint8_t client[])
{
  int i;
  for(i = 0; i <= client_entry_last; i++)
  {
    if(mac_is_equal(probe_array[i].client_addr, client))
    {
      // check if bssid is first in list...
      return (mac_is_equal(bssid, probe_array[i].bssid_addr));
    }
  }
  return 0;
}

void kick_clients(uint8_t bssid[])
{
  // Seach for BSSID
  int i;
  for(i = 0; i <= client_entry_last; i++)
  {
    if(mac_is_equal(client_array[i].bssid_addr, bssid))
    {
      break;
    }
  }

  // Go threw clients
  int j;
  for(j = i; j <= client_entry_last; j++)
  {
    if(!mac_is_equal(client_array[j].bssid_addr, bssid))
    {
      break;
    }
    if(kick_client(bssid, client_array[j].client_addr))
    {
      /*
        TODO: KICK ONLY FROM ONE BSSID?
      */
      printf("KICKING CLIENT!!!!!!!!!!!!!\n");
      //del_client(client_array[j].client_addr, 5, 1, 60000);
    } else 
    {
      printf("STAAAY CLIENT!!!!!!!!!!!!!\n");
    }
  }
}

int client_array_go_next_help(char sort_order[], int i, client entry,
                 client next_entry) {
  switch (sort_order[i]) {
    // bssid-mac
    case 'b':
      return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr) &&
             mac_is_equal(entry.client_addr, next_entry.client_addr);
      break;

    // client-mac
    case 'c':
      return mac_is_greater(entry.client_addr, next_entry.client_addr);
      break;

    // frequency
    // mac is 5 ghz or 2.4 ghz?
   // case 'f':
    //  return //entry.freq < next_entry.freq &&
    //    entry.freq < 5000 &&
    //    next_entry.freq >= 5000 &&
    //    //entry.freq < 5 &&
    //    mac_is_equal(entry.client_addr, next_entry.client_addr);
    //  break;

    // signal strength (RSSI)
    //case 's':
    //  return entry.signal < next_entry.signal &&
    //         mac_is_equal(entry.client_addr, next_entry.client_addr);
    //  break;

    default:
      return 0;
      break;
  }
}

int client_array_go_next(char sort_order[], int i, client entry,
            client next_entry) {
  int conditions = 1;
  for (int j = 0; j < i; j++) {
    i &= !(client_array_go_next(sort_order, j, entry, next_entry));
  }
  return conditions && client_array_go_next_help(sort_order, i, entry, next_entry);
}

void client_array_insert(client entry)
{
  if(client_entry_last == -1)
  {
    client_array[0] = entry;
    client_entry_last++;
    return;
  }
  
  int i;
  for(i = 0; i <= client_entry_last; i++)
  {
    if(!client_array_go_next("bc", 2, entry, client_array[i]))
    {
      break;
    }
  }
  for(int j = client_entry_last; j >= i; j--)
  {
    if(j + 1 <= ARRAY_LEN)
    {
      client_array[j + 1] = client_array[j]; 
    }
  }
  client_array[i] = entry;

  if(client_entry_last < ARRAY_LEN)
  {
    client_entry_last++;    
  }
}

client* client_array_delete(client entry)
{
  
  int i;
  int found_in_array = 0;
  client* tmp = NULL;

  if(client_entry_last == -1)
  {
    return NULL;
  }

  for(i = 0; i <= client_entry_last; i++)
  {
    if(mac_is_equal(entry.bssid_addr, client_array[i].bssid_addr) &&
        mac_is_equal(entry.client_addr, client_array[i].client_addr))
    {
      found_in_array = 1;
      tmp = &client_array[i];
      break;
    }
  }

  for(int j = i; j <= client_entry_last; j++)
  {
    client_array[j] = client_array[j + 1]; 
  }

  if(client_entry_last > -1 && found_in_array)
  {
    client_entry_last--;
  }
  return tmp;
}


void probe_array_insert(probe_entry entry)
{
  if(probe_entry_last == -1)
  {
    probe_array[0] = entry;
    probe_entry_last++;
    return;
  }
  
  int i;
  for(i = 0; i <= probe_entry_last; i++)
  {
    if(!go_next(sort_string, SORT_NUM, entry, probe_array[i]))
    {
      break;
    }
  }
  for(int j = probe_entry_last; j >= i; j--)
  {
    if(j + 1 <= ARRAY_LEN)
    {
      probe_array[j + 1] = probe_array[j]; 
    }
  }
  probe_array[i] = entry;

  if(probe_entry_last < ARRAY_LEN)
  {
    probe_entry_last++;    
  }
}

probe_entry* probe_array_delete(probe_entry entry)
{
  int i;
  int found_in_array = 0;
  probe_entry* tmp = NULL;

  if(probe_entry_last == -1)
  {
    return NULL;
  }

  for(i = 0; i <= probe_entry_last; i++)
  {
    if(mac_is_equal(entry.bssid_addr, probe_array[i].bssid_addr) &&
        mac_is_equal(entry.client_addr, probe_array[i].client_addr))
    {
      found_in_array = 1;
      tmp = &probe_array[i];
      break;
    }
  }

  for(int j = i; j <= probe_entry_last; j++)
  {
    probe_array[j] = probe_array[j + 1]; 
  }

  if(probe_entry_last > -1 && found_in_array)
  {
    probe_entry_last--;
  }
  return tmp;
}

void print_array()
{
  printf("------------------\n");
  printf("Probe Entry Last: %d\n", probe_entry_last);
  for(int i = 0; i <= probe_entry_last; i++)
  {
    print_probe_entry(probe_array[i]);
  }
  printf("------------------\n");
}

void insert_to_array(probe_entry entry, int inc_counter) 
{
  pthread_mutex_lock(&probe_array_mutex);

  entry.time = time(0);
  entry.counter = 0;
  probe_entry* tmp = probe_array_delete(entry);

  if(tmp != NULL)
  {
    entry.counter = tmp->counter;
  }

  if (inc_counter)
  {
    entry.counter++;
  }

  probe_array_insert(entry);

  pthread_mutex_unlock(&probe_array_mutex); 
}

void remove_old_client_entries(time_t current_time, long long int threshold)
{
  for(int i = 0; i < probe_entry_last; i++)
  {
    if (client_array[i].time < current_time - threshold)
    {
      client_array_delete(client_array[i]);
    }
  }
}

void remove_old_probe_entries(time_t current_time, long long int threshold)
{
  for(int i = 0; i < probe_entry_last; i++)
  {
    if (probe_array[i].time < current_time - threshold)
    {
      probe_array_delete(probe_array[i]);
    }
  }
}
 
void *remove_array_thread(void *arg) {
  while (1) {
    sleep(TIME_THRESHOLD);
    pthread_mutex_lock(&probe_array_mutex);
    printf("[Thread] : Removing old entries!\n");
    remove_old_probe_entries(time(0), TIME_THRESHOLD);
    pthread_mutex_unlock(&probe_array_mutex);
  }
  return 0;
}

void *remove_client_array_thread(void *arg) {
  while (1) {
    sleep(TIME_THRESHOLD_CLIENT);
    pthread_mutex_lock(&client_array_mutex);
    printf("[Thread] : Removing old client entries!\n");
    remove_old_client_entries(time(0), TIME_THRESHOLD_CLIENT);
    pthread_mutex_unlock(&client_array_mutex);
  }
  return 0;
}


void insert_client_to_array(client entry)
{
  pthread_mutex_lock(&client_array_mutex);
  entry.time = time(0);

  client_array_delete(entry);
  client_array_insert(entry);

  pthread_mutex_unlock(&client_array_mutex);
}








node *delete_probe_req(node **ret_remove, node *head, uint8_t bssid_addr[],
                       uint8_t client_addr[]);
int mac_is_first_in_list(node *head, uint8_t bssid_addr[],
                         uint8_t client_addr[]);
node *remove_node(node *head, node *curr, node *prev);
node *remove_old_entries(node *head, time_t current_time,
                         long long int threshold);
void print_list_with_head(node *head);

void insert_to_list(probe_entry entry, int inc_counter) {
  pthread_mutex_lock(&list_mutex);

  entry.time = time(0);
  entry.counter = 0;

  
  // first delete probe request
  // probe_list_head = remove_old_entries(probe_list_head, time(0),
  // TIME_THRESHOLD);
  node *tmp_probe_req = NULL;
  probe_list_head = delete_probe_req(&tmp_probe_req, probe_list_head,
                                     entry.bssid_addr, entry.client_addr);

  if (tmp_probe_req) {
    // local ubus
    tmp_probe_req->data.signal = entry.signal;
    tmp_probe_req->data.time = entry.time;
    if (inc_counter) {
      // when network don't increase counter...
      tmp_probe_req->data.counter++;
    }

    // is this correct?
    probe_list_head = insert(probe_list_head, tmp_probe_req->data);
    free(tmp_probe_req);
  } else {
    printf("New entry!\n");
    probe_list_head = insert(probe_list_head, entry);
  }

  pthread_mutex_unlock(&list_mutex);
}

int go_next_help(char sort_order[], int i, probe_entry entry,
                 probe_entry next_entry) {
  switch (sort_order[i]) {
    // bssid-mac
    case 'b':
      return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr) &&
             mac_is_equal(entry.client_addr, next_entry.client_addr);
      break;

    // client-mac
    case 'c':
      return mac_is_greater(entry.client_addr, next_entry.client_addr);
      break;

    // frequency
    // mac is 5 ghz or 2.4 ghz?
    case 'f':
      return //entry.freq < next_entry.freq &&
        entry.freq < 5000 &&
        next_entry.freq >= 5000 &&
        //entry.freq < 5 &&
        mac_is_equal(entry.client_addr, next_entry.client_addr);
      break;

    // signal strength (RSSI)
    case 's':
      return entry.signal < next_entry.signal &&
             mac_is_equal(entry.client_addr, next_entry.client_addr);
      break;

    default:
      return 0;
      break;
  }
}

int go_next(char sort_order[], int i, probe_entry entry,
            probe_entry next_entry) {
  int conditions = 1;
  for (int j = 0; j < i; j++) {
    i &= !(go_next(sort_order, j, entry, next_entry));
  }
  return conditions && go_next_help(sort_order, i, entry, next_entry);
}

node *insert(node *head, probe_entry entry) {
  node *temp, *prev, *next;
  temp = (node *)malloc(sizeof(node));
  temp->data = entry;
  temp->ptr = NULL;

  // length of sorting string
  // char sort_string[] = "cfsb";
  int i = 0;

  if (!head) {
    head = temp;
  } else {
    prev = NULL;
    next = head;
    while (next) {
      if (go_next(sort_string, i, entry, next->data)) {
        prev = next;
        next = next->ptr;
      } else if (i < strlen(sort_string)) {
        i++;
      } else {
        break;
      }
    }
    if (!next) {
      prev->ptr = temp;
    } else {
      if (prev) {
        temp->ptr = prev->ptr;
        prev->ptr = temp;
      } else {
        temp->ptr = head;
        head = temp;
      }
    }
  }
  return head;
}

node *delete_probe_req(node **ret_remove, node *head, uint8_t bssid_addr[],
                       uint8_t client_addr[]) {
  if (!head) {
    return head;
  }

  if (mac_is_equal(client_addr, head->data.client_addr) &&
      mac_is_equal(bssid_addr, head->data.bssid_addr)) {
    node *temp = head;
    head = head->ptr;
    *ret_remove = temp;
    // don't free pointer
    // free(temp);
    return head;
  }

  node *prev = NULL;
  node *next = head;
  while (next) {
    if (mac_is_greater(next->data.client_addr, client_addr)) {
      break;
    }

    if (mac_is_equal(client_addr, next->data.client_addr) &&
        mac_is_equal(bssid_addr, next->data.bssid_addr)) {
      node *temp = next;
      prev->ptr = next->ptr;
      // free(temp);
      *ret_remove = temp;
      return head;
    }
    prev = next;
    next = next->ptr;
  }
  return head;
}

void *remove_thread(void *arg) {
  while (1) {
    sleep(TIME_THRESHOLD);
    pthread_mutex_lock(&list_mutex);
    printf("[Thread] : Removing old entries!\n");
    probe_list_head =
        remove_old_entries(probe_list_head, time(0), TIME_THRESHOLD);
    pthread_mutex_unlock(&list_mutex);
    // print_list();
  }
  return 0;
}

node *remove_old_entries(node *head, time_t current_time,
                         long long int threshold) {
  if (head) {
    node *prev = NULL;
    node *next = head;
    while (next) {
      if (next->data.time < current_time - threshold) {
        head = remove_node(head, next, prev);
        // print_list_with_head(head);
        if (prev == NULL)  // removed head
        {
          next = head;
        } else {
          next = prev->ptr;
        }
      } else {
        prev = next;
        next = next->ptr;
      }
    }
  }
  return head;
}

// return headpointer
node *remove_node(node *head, node *curr, node *prev) {
  if (curr == head) {
    node *temp = head;
    head = head->ptr;
    free(temp);
  } else {
    node *temp = curr;
    prev->ptr = curr->ptr;
    free(temp);
  }
  // printf("Removed old entry!\n");
  return head;
}

int mac_is_first_in_list(node *head, uint8_t bssid_addr[],
                         uint8_t client_addr[]) {
  if (!head) {
    return 1;
  }
  node *next = head;
  while (next) {
    if (mac_is_greater(next->data.client_addr, client_addr)) {
      break;
    }

    if (mac_is_equal(client_addr, next->data.client_addr)) {
      print_probe_entry(next->data);
      return mac_is_equal(bssid_addr, next->data.bssid_addr);
    }
    next = next->ptr;
  }
  return 0;
}

int mac_first_in_probe_list(uint8_t bssid_addr[], uint8_t client_addr[]) {
  pthread_mutex_lock(&list_mutex);
  int ret = mac_is_first_in_list(probe_list_head, bssid_addr, client_addr);
  pthread_mutex_unlock(&list_mutex);
  return ret;
}

void free_list(node *head) {
  node *prev = head;
  node *cur = head;
  while (cur) {
    prev = cur;
    cur = prev->ptr;
    free(prev);
  }
}

int mac_is_equal(uint8_t addr1[], uint8_t addr2[]) {
  return memcmp(addr1, addr2, ETH_ALEN * sizeof(uint8_t)) == 0;
}

int mac_is_greater(uint8_t addr1[], uint8_t addr2[]) {
  for (int i = 0; i < ETH_ALEN; i++) {
    if (addr1[i] > addr2[i]) {
      return 1;
    }
    if (addr1[i] < addr2[i]) {
      return 0;
    }

    // if equal continue...
  }
  return 0;
}

void print_list_with_head(node *head) {
  pthread_mutex_lock(&list_mutex);
  printf("------------------\n");
  if (head) {
    node *next;
    next = head;
    while (next) {
      print_probe_entry(next->data);
      next = next->ptr;
    }
  }
  printf("------------------\n");
  pthread_mutex_unlock(&list_mutex);
}

void print_list() {
  pthread_mutex_lock(&list_mutex);
  printf("------------------\n");
  node *head = probe_list_head;
  if (head) {
    node *next;
    next = head;
    while (next) {
      print_probe_entry(next->data);
      next = next->ptr;
    }
  }
  printf("------------------\n");
  pthread_mutex_unlock(&list_mutex);
}

void print_probe_entry(probe_entry entry) {
  char mac_buf_ap[20];
  char mac_buf_client[20];
  char mac_buf_target[20];

  sprintf(mac_buf_ap, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.bssid_addr));
  sprintf(mac_buf_client, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.client_addr));
  sprintf(mac_buf_target, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.target_addr));

  printf(
      "bssid_addr: %s, client_addr: %s, target_addr: %s, signal: %d, freq: "
      "%d, counter: %d\n",
      mac_buf_ap, mac_buf_client, mac_buf_target, entry.signal, entry.freq,
      entry.counter);
}

void print_client_entry(client entry) {
  char mac_buf_ap[20];
  char mac_buf_client[20];

  sprintf(mac_buf_ap, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.bssid_addr));
  sprintf(mac_buf_client, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.client_addr));

  printf("bssid_addr: %s, client_addr: %s, freq: %d, ht_supported: %d, vht_supported: %d, ht: %d, vht: %d\n",
      mac_buf_ap, mac_buf_client, entry.freq, entry.ht_supported, entry.vht_supported, entry.ht, entry.vht);
}

void print_client_array() {
  printf("--------Clients------\n");
  printf("Probe Entry Last: %d\n", client_entry_last);
  for(int i = 0; i <= client_entry_last; i++)
  {
    print_client_entry(client_array[i]);
  }
  printf("------------------\n");
}