#ifndef _MEASURED_RABBITCFG_H
#define _MEASURED_RABBITCFG_H

// XXX generate paths
#define RABBITMQCTL "/usr/sbin/rabbitmqctl"

int setup_rabbitmq_user(char *username);
int setup_rabbitmq_shovel(char *ampname, char *collector, int port,
        char *cacert, char *cert, char *key, char *exchange, char *routingkey);

#endif
