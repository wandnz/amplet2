#ifndef _MEASURED_NAMETABLE_H
#define _MEASURED_NAMETABLE_H

#include <libwandevent.h>
#include "schedule.h"

#define MAX_NAMETABLE_LINE 128
#define NAMETABLE_FILE AMP_CONFIG_DIR "/nametable"
#define NAMETABLE_DELIMITER " \n"

#define MAX_NAMETABLE_HOSTS 1024



/*
 * Name table entry containing both the name and an address structure. 
 * Currently a singly linked list, though this should probably improve.
 */
struct name_entry {
    char *name;
    struct addrinfo *addr;
    struct name_entry *next;
};
typedef struct name_entry name_entry_t;


void read_nametable_file(void);
void setup_nametable_refresh(wand_event_handler_t *ev_hdl);
struct addrinfo *name_to_address(char *name);
char *address_to_name(struct addrinfo *address);
void clear_nametable(void);

#endif
