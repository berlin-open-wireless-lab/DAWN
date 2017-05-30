#include "datastorage.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int mac_is_equal(uint8_t addr1[], uint8_t addr2[]);
int mac_is_greater(uint8_t addr1[], uint8_t addr2[]);
void print_probe_entry(probe_entry entry);
int delete_probe_req(node* head, uint8_t bssid_addr[], uint8_t client_addr[]);
int mac_is_first_in_list(node* head, uint8_t bssid_addr[], uint8_t client_addr[]);

void insert_to_list(probe_entry entry)
{
    pthread_mutex_lock(&list_mutex);

    // first delete probe request
    delete_probe_req(probe_list_head, entry.bssid_addr, entry.client_addr);
    probe_list_head = insert(probe_list_head, entry);
    
    pthread_mutex_unlock(&list_mutex);
}

node* insert(node* head, probe_entry entry) {
    node *temp, *prev, *next;
    temp = (node*)malloc(sizeof(node));
    temp->data = entry;
    temp->ptr = NULL;

    if(!head)
    {
        head = temp;
    } 
    else
    {
        // TODO: make sorting as startup parameter

        prev = NULL;
        next = head;
        while(next
            && (
                mac_is_greater(entry.client_addr, next->data.client_addr) 
                || (
                    mac_is_equal(entry.client_addr, next->data.client_addr)
                    //&& !mac_is_equal(entry.bssid_addr, next->data.bssid_addr) 
                    && entry.signal < next->data.signal
                    )
                || (
                    mac_is_equal(entry.client_addr, next->data.client_addr)
                    //&& !mac_is_equal(entry.bssid_addr, next->data.bssid_addr) 
                    && entry.signal == next->data.signal
                    && entry.freq < next->data.freq
                    )

                || (
                    mac_is_equal(entry.client_addr, next->data.client_addr)
                    //&& !mac_is_equal(entry.bssid_addr, next->data.bssid_addr) 
                    && entry.signal == next->data.signal
                    && entry.freq == next->data.freq
                    && mac_is_greater(entry.bssid_addr, next->data.bssid_addr)
                    )
                )
            )
        {
            /*
            if(mac_is_smaller(entry.client_addr, next->data.client_addr)
            {
                break;
            }
            else if(mac_is_equal(entry.client_addr, next->data.client_addr)
            {
                if(entry.freq >= next->data.freq)
                {


                    if(mac_is_smaller(entry.bssid_addr, next->data.bssid_addr))
                    {
                        break;
                    }
                    else if(mac_is_equal(entry.bssid_addr, next->data.bssid_addr))
                    {
                        if()
                    }
                }
            }*/
            /*
            if(mac_is_greater(entry.client_addr, next->data.client_addr))
            {
                if(entry.freq > next->data.freq)
                {
                    if(entry.signal >= next->data.signal)
                    {
                        if(mac_is_greater(entry.bssid_addr, next->data.bssid_addr))
                        {
                            break;
                        }
                    }
                }
                
            }
            */


            prev = next;
            next = next->ptr;
        }
        if(next && mac_is_equal(entry.client_addr,next->data.client_addr) 
            && mac_is_equal(entry.bssid_addr, next->data.bssid_addr)
            )//&& entry.freq == next->data.freq)
        {
            next->data.signal = entry.signal;
        }
        else if(!next){
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

int delete_probe_req(node* head, uint8_t bssid_addr[], uint8_t client_addr[]) 
{

    if(!head)
    {
        return 1;
    } 

    if(mac_is_equal(client_addr, head->data.client_addr)
        && mac_is_equal(bssid_addr, head->data.bssid_addr))
    {
        node *temp = head;
        head = head->ptr;
        free(temp);
        return 1; 
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
            return 1;
        }
        prev = next;
        next = next->ptr;    
    }
    return 0;
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
    node* head = probe_list_head;
    if(!head)
    {
        return;
    }
    node* next;
    next = head;
    while(next)
    {
        print_probe_entry(next->data);
        next = next->ptr;
    }
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