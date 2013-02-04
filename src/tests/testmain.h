#ifndef _MEASURED_TESTMAIN_H
#define _MEASURED_TESTMAIN_H

/* 
 * FIXME is this the best way to get a new version of this function in here?
 * There is currently no header file associated with standalone tests that
 * this could go in, maybe we need one?
 */
char *address_to_name(struct addrinfo *address);

#endif
