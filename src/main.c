#include <libubus.h>
#include <stdio.h>

#include "datastorage.h"
#include "networksocket.h"
#include "ubus.h"

#define BUFSIZE 17
#define BUFSIZE_DIR 255

int main(int argc, char **argv) {
  const char *ubus_socket = NULL;
  int ch;

  char opt_broadcast_ip[BUFSIZE];
  char opt_broadcast_port[BUFSIZE];
  char opt_hostapd_dir[BUFSIZE_DIR];

  while ((ch = getopt(argc, argv, "cs:p:i:b:o:h:")) != -1) {
    switch (ch) {
      case 's':
        ubus_socket = optarg;
        break;
      case 'p':
        snprintf(opt_broadcast_port, BUFSIZE, "%s", optarg);
        printf("broadcast port: %s\n", opt_broadcast_port);
        break;
      case 'i':
        snprintf(opt_broadcast_ip, BUFSIZE, "%s", optarg);
        printf("broadcast ip: %s\n", opt_broadcast_ip);
        break;
      case 'o':
        snprintf(sort_string, SORT_NUM, "%s", optarg);
        printf("sort string: %s\n", sort_string);
      case 'h':
        snprintf(opt_hostapd_dir, BUFSIZE_DIR, "%s", optarg);
        printf("hostapd dir: %s\n", opt_hostapd_dir);
      default:
        break;
    }
  }

  argc -= optind;
  argv += optind;

  if (pthread_mutex_init(&list_mutex, NULL) != 0) {
    printf("\n mutex init failed\n");
    return 1;
  }

  if (pthread_mutex_init(&probe_array_mutex, NULL) != 0) {
    printf("\n mutex init failed\n");
    return 1;
  }  

  init_socket_runopts(opt_broadcast_ip, opt_broadcast_port, 0);

  //pthread_t tid;
  //pthread_create(&tid, NULL, &remove_thread, NULL);

  dawn_init_ubus(ubus_socket, opt_hostapd_dir);

  // free ressources
  pthread_mutex_destroy(&list_mutex);
  free_list(probe_list_head);

  return 0;
}