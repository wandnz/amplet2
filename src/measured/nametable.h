#ifndef _MEASURED_NAMETABLE_H
#define _MEASURED_NAMETABLE_H

#include <libwandevent.h>
#include "schedule.h"

#define MAX_NAMETABLE_LINE 128
#define NAMETABLE_FILE AMP_CONFIG_DIR "/nametable"
#define NAMETABLE_DELIMITER " \n"

#define MAX_NAMETABLE_HOSTS 1024

struct nametable_item {
    struct addrinfo *addr;
    struct nametable_item *next;
    uint8_t count;
};
typedef struct nametable_item nametable_t;

void read_nametable_file(void);
void setup_nametable_refresh(wand_event_handler_t *ev_hdl);
nametable_t *name_to_address(char *name);
void clear_nametable(void);

#endif
