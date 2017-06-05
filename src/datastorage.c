#include "datastorage.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int go_next_help(char sort_order[], int i, probe_entry entry, probe_entry next_entry);
int go_next(char sort_order[], int i, probe_entry entry, probe_entry next_entry);
int mac_is_equal(uint8_t addr1[], uint8_t addr2[]);
int mac_is_greater(uint8_t addr1[], uint8_t addr2[]);
void print_probe_entry(probe_entry entry);
node* delete_probe_req(node* head, uint8_t bssid_addr[], uint8_t client_addr[]);
int mac_is_first_in_list(node* head, uint8_t bssid_addr[], uint8_t client_addr[]);
node* remove_node(node* head, node* curr, node* prev);
node* remove_old_entries(node* head, time_t current_time, long long int threshold);

void insert_to_list(probe_entry entry)
{
    pthread_mutex_lock(&list_mutex);

    entry.time = time(0);

    // first delete probe request
    probe_list_head = delete_probe_req(probe_list_head, entry.bssid_addr, entry.client_addr);
    probe_list_head = insert(probe_list_head, entry);
    
    pthread_mutex_unlock(&list_mutex);
}

int go_next_help(char sort_order[], int i, probe_entry entry, probe_entry next_entry)
{
    switch(sort_order[i])
    {
        // bssid-mac
        case 'b':
            return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr) && mac_is_equal(entry.client_addr, next_entry.client_addr);
            break;

        // client-mac
        case 'c':
            return mac_is_greater(entry.client_addr, next_entry.client_addr);
            break;

        // frequency
        case 'f':
            return entry.freq < next_entry.freq && mac_is_equal(entry.client_addr, next_entry.client_addr);
            break;
        
        // signal strength (RSSI)
        case 's':
            return entry.signal < next_entry.signal && mac_is_equal(entry.client_addr, next_entry.client_addr);         
            break;

        default:
            return 0;
            break;
    }
}

int go_next(char sort_order[], int i, probe_entry entry, probe_entry next_entry)
{
    int conditions = 1;
    for(int j = 0; j < i; j++)
    {
        i &= !(go_next(sort_order, j, entry, next_entry));
    }
    return conditions && go_next_help(sort_order, i, entry, next_entry);
}

node* insert(node* head, probe_entry entry) {
    node *temp, *prev, *next;
    temp = (node*)malloc(sizeof(node));
    temp->data = entry;
    temp->ptr = NULL;


    // length of sorting string
    //char sort_string[] = "cfsb";
    int i = 0;

    if(!head)
    {
        head = temp;
    } 
    else
    {
        prev = NULL;
        next = head;
        while(next)
        {
            if(go_next(sort_string, i, entry, next->data))
            {
                prev = next;
                next = next->ptr;
            } else if(i < strlen(sort_string)) {
                i++;
            } else 
            {
                break;
            }

        }
        if(!next){
            prev->ptr = temp;
        }
        else
        {
            if(prev) {
                temp->ptr = prev->ptr;
                prev-> ptr = temp;
            } else {
                temp->ptr = head;
                head = temp;
            }            
        }   
    }
    return head;

}

node* delete_probe_req(node* head, uint8_t bssid_addr[], uint8_t client_addr[]) 
{
    if(!head)
    {
        return head;
    } 

    if(mac_is_equal(client_addr, head->data.client_addr)
        && mac_is_equal(bssid_addr, head->data.bssid_addr))
    {
        node *temp = head;
        head = head->ptr;
        free(temp);
        return head; 
    }

    node *prev = NULL;
    node *next = head;
    while(next)
    {
        if(mac_is_greater(next->data.client_addr, client_addr))
        {
            break;
        }

        if(mac_is_equal(client_addr, next->data.client_addr)
            && mac_is_equal(bssid_addr, next->data.bssid_addr))
        {
            node *temp = next;
            prev->ptr = next->ptr;
            free(temp);
            return head;
        }
        prev = next;
        next = next->ptr;    
    }
    return head;
}

void *remove_thread(void *arg)
{
    while(1)
    {
        sleep(TIME_THRESHOLD);
        pthread_mutex_lock(&list_mutex);
        printf("Removing old entries now!\n");
        probe_list_head = remove_old_entries(probe_list_head, time(0), TIME_THRESHOLD);
        pthread_mutex_unlock(&list_mutex);
        print_list();
    }
    return 0;
}

node* remove_old_entries(node* head, time_t current_time, long long int threshold)
{
    if(head)
    {
        node *prev = NULL;
        node *next = head;
        while(next)
        {
            printf("Going next...\n");
            printf("Entry Time: %ld, Curr Time: %lld\n", next->data.time, current_time - threshold);
            if(next->data.time < current_time - threshold)
            {
                printf("Removing node!\n");
                head = remove_node(head, next, prev);
            }
            prev = next;
            next = next->ptr;    
        }
    }
    
    return head;
}

// return headpointer
node* remove_node(node* head, node* curr, node* prev)
{
    if(curr == head)
    {
        node *temp = head;
        head = head->ptr;
        free(temp);
    } 
    else 
    {
        node *temp = curr;
        prev->ptr = curr->ptr;
        free(temp);
    }
    printf("Removed old entry!\n");
    return head;
}

int mac_is_first_in_list(node* head, uint8_t bssid_addr[], uint8_t client_addr[]) 
{
    if(!head)
    {
        return 1;
    } 
    node *next = head;
    while(next)
    {
        if(mac_is_greater(next->data.client_addr, client_addr))
        {
            break;
        }

        if(mac_is_equal(client_addr, next->data.client_addr))
        {
            print_probe_entry(next->data);
            return mac_is_equal(bssid_addr, next->data.bssid_addr);
        }
        next = next->ptr;   
    }
    return 0;
}

int mac_first_in_probe_list(uint8_t bssid_addr[], uint8_t client_addr[])
{
    pthread_mutex_lock(&list_mutex);  
    int ret = mac_is_first_in_list(probe_list_head, bssid_addr, client_addr);
    pthread_mutex_unlock(&list_mutex);
    return ret;
}

void free_list(node *head) {
    node *prev = head;
    node *cur = head;
    while(cur) {
        prev = cur;
        cur = prev->ptr;
        free(prev);
    }       
}

int mac_is_equal(uint8_t addr1[], uint8_t addr2[])
{
    return memcmp(addr1, addr2, ETH_ALEN * sizeof(uint8_t)) == 0;
}

int mac_is_greater(uint8_t addr1[], uint8_t addr2[])
{
    for(int i = 0; i < ETH_ALEN; i++)
    {
        if(addr1[i] > addr2[i])
        {
            return 1;
        }
        if(addr1[i] < addr2[i])
        {
            return 0;
        }

        // if equal continue...
    }
    return 0;
}

void print_list()
{
    pthread_mutex_lock(&list_mutex);  
    printf("------------------\n");
    node* head = probe_list_head;
    if(!head)
    {
        printf("------------------\n");
        return;
    }
    node* next;
    next = head;
    while(next)
    {
        print_probe_entry(next->data);
        next = next->ptr;
    }
    printf("------------------\n");
    pthread_mutex_unlock(&list_mutex);
}

void print_probe_entry(probe_entry entry)
{        
    char mac_buf_ap[20];
    char mac_buf_client[20];
    char mac_buf_target[20];

    sprintf(mac_buf_ap, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.bssid_addr));
    sprintf(mac_buf_client, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.client_addr));
    sprintf(mac_buf_target, "%x:%x:%x:%x:%x:%x", MAC2STR(entry.target_addr));
    
    printf("bssid_addr: %s, client_addr: %s, target_addr: %s, signal: %d, freq: %d\n", 
    mac_buf_ap, mac_buf_client, mac_buf_target, entry.signal, entry.freq);
    
}