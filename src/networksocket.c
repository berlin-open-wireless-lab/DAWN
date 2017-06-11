#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libconfig.h>   

#include <libubox/blobmsg_json.h>

#include "networksocket.h"
#include "datastorage.h"
#include "ubus.h"


/* Network Defines */
#define MAX_RECV_STRING   255
#define NET_CONFIG_PATH     "/etc/wlancontroller/networkconfig.conf"

/* Network Attributes */
int sock;                         
struct sockaddr_in broadcast_addr; 
const char *broadcast_ip;      
unsigned short broadcast_port;
int broadcast_permission;
char recv_string[MAX_RECV_STRING+1];
int recv_stringLen;
void* receive_msg(void *args);

int init_socket_runopts(char* _broadcast_ip, char* _broadcast_port){

    int tmp_broacast_port = atoi(_broadcast_port);
    init_socket(_broadcast_ip, tmp_broacast_port);

    pthread_t sniffer_thread;
    if( pthread_create( &sniffer_thread , NULL ,  receive_msg , NULL) )
    {
        fprintf(stderr, "Could not create receiving thread!");
        return -1;
    }

    fprintf(stdout, "Connected to %s:%d\n", _broadcast_ip, tmp_broacast_port);

    return 0;
}

int init_socket_conffile(){
    const char *_broadcast_ip;
    int _broacast_port;

    config_t cfg;
    //config_setting_t *setting;
    const char *config_file_name = NET_CONFIG_PATH;

    config_init(&cfg);

    /* Read the file. If there is an error, report it and exit. */
    if(! config_read_file(&cfg, config_file_name))
    {
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return(EXIT_FAILURE);
    }

    if(config_lookup_string(&cfg, "broadcast_ip", &_broadcast_ip))
        printf("Broadcast IP: %s\n", _broadcast_ip);
    else
        fprintf(stderr, "No 'name' setting in configuration file.\n");

    if(config_lookup_int(&cfg, "broacast_port", &_broacast_port))
        printf("Broadcast Port: %d\n\n", _broacast_port);
    else
        fprintf(stderr, "No 'name' setting in configuration file.\n");

    init_socket(_broadcast_ip, _broacast_port);

    config_destroy(&cfg);

    pthread_t sniffer_thread;
    if( pthread_create( &sniffer_thread , NULL ,  receive_msg , NULL) )
    {
        fprintf(stderr, "Could not create receiving thread!");
        return -1;
    }
    return 0;
}

void* receive_msg(void *args)
{
    while(1)
    {
        if ((recv_stringLen = recvfrom(sock, recv_string, MAX_RECV_STRING, 0, NULL, 0)) < 0)
        {
            fprintf(stderr, "Could not receive message!");
            continue;
        }
    
        printf("[WC] Network-Received: %s\n", recv_string);

        probe_entry prob_req;
        struct blob_buf b;

        blob_buf_init(&b, 0);
        blobmsg_add_json_from_string(&b, recv_string);
        
        recv_string[recv_stringLen] = '\0';
        char *str;
        str = blobmsg_format_json(b.head, true);
        printf("Parsed: '%s'\n", str);
        parse_to_probe_req(b.head, &prob_req);

        // insert to list 
        insert_to_list(prob_req);
    }
}



int init_socket(const char *_broadcast_ip, unsigned short _broadcast_port)
{
	broadcast_ip = _broadcast_ip;
	broadcast_port = _broadcast_port;

    /* Create socket */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
    	fprintf(stderr, "Failed to create socket.\n");
    	return -1;
    }

    /* Allow broadcast */
    broadcast_permission = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_permission, 
          sizeof(broadcast_permission)) < 0)
    {
    	fprintf(stderr, "Failed to create socket.\n");
    	return -1;
    }

    /* Construct Address */
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = inet_addr(broadcast_ip);
    broadcast_addr.sin_port = htons(broadcast_port);

    if (bind(sock, (struct sockaddr *) &broadcast_addr, sizeof(broadcast_addr)) < 0)
    {
        fprintf(stderr, "Binding socket failed!\n");
        return -1;
    }
    return 0;
}

int send_string(char *msg)
{
	int msglen = strlen(msg);
	if (sendto(sock, msg, msglen, 0, (struct sockaddr *) 
               &broadcast_addr, sizeof(broadcast_addr)) != msglen)
	{
    	fprintf(stderr, "Failed to send message.\n");
		return -1;
	}
    return 0;
}

void close_socket()
{
	close(sock);
}

