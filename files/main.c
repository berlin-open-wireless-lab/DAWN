#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>


int main(int argc, char **argv)
{
  config_t cfg;
  config_setting_t *root, *setting, *movie;

  config_init(&cfg);

  /* Read the file. If there is an error, report it and exit. */
  if(! config_read_file(&cfg, "dawn.config"))
  {
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return(EXIT_FAILURE);
	}
	
	printf("READ CONFIG!!!\n");
	
	root = config_root_setting(&cfg);
	
	int ht_support;
	if (config_lookup_int(&cfg, "ht_support", &ht_support))
		printf("Broadcast Port: %d\n\n", ht_support);
	else
		fprintf(stderr, "No 'name' setting in configuration file.\n");


}