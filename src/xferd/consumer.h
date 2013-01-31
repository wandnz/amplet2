#ifndef _XFERD_CONSUMER_H
#define _XFERD_CONSUMER_H

static int running = 1;

void setup_channel(void);
int setup_queue(char *name);
int consumer(void);

#endif
