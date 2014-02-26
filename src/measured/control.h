#ifndef _MEASURED_CONTROL_H
#define _MEASURED_CONTROL_H

// TODO good default values for these things
/* control port is a string that gets given to getaddrinfo() */
#define CONTROL_PORT "8869"

/* Allow the test server to run slightly longer than the client test */
#define TEST_SERVER_EXTRA_TIME 60

int initialise_control_socket(char *address, char *port);
void control_establish_callback(struct wand_fdcb_t *handle, enum wand_eventtype_t ev);

#endif
