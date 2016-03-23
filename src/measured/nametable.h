#ifndef _MEASURED_NAMETABLE_H
#define _MEASURED_NAMETABLE_H

#include <stdint.h>
#include <libwandevent.h>

#define MAX_NAMETABLE_LINE 128
#define NAMETABLE_DIR AMP_CONFIG_DIR "/nametables"
#define NAMETABLE_DELIMITER " \n"

#define MAX_NAMETABLE_HOSTS 1024

struct nametable_item {
    struct addrinfo *addr;
    struct nametable_item *next;
    uint8_t count;
};
typedef struct nametable_item nametable_t;

void read_nametable_dir(char *directory);
void setup_nametable_refresh(wand_event_handler_t *ev_hdl);
nametable_t *name_to_address(char *name);
void clear_nametable(void);
#if UNIT_TEST
void nametable_test_insert_nametable_entry(char *name, struct addrinfo *info);
#endif

#endif
