#ifndef _COMMON_AMPRESOLV_H
#define _COMMON_AMPRESOLV_H

/*
 * These are taken from eglibc-2.13/resolv/res_send.c to work with the
 * modified functions also taken from there.
 */
#define EXT(res) ((res)->_u._ext)

#ifndef __ASSUME_SOCK_CLOEXEC
static int __have_o_nonblock;
#else
# define __have_o_nonblock 0
#endif


int update_nameservers(char *servers[], int count);
void open_nameserver_sockets(void);
void init_default_nameservers(void);

#endif
