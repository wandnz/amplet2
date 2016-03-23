#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/bio.h>

#include <google/protobuf-c/protobuf-c.h>

#include "config.h"
#include "testlib.h"
#include "debug.h"
#include "tests.h"
#include "modules.h"
#include "messaging.h"
#include "global.h"



/*
 * The ELF binary layout means we should have all of the command line
 * arguments and the environment all contiguous in the stack. We can take
 * over all of that space and replace it with whatever program name or
 * description that we want, and relocate the environment to a new location.
 *
 * This approach makes it not portable, but for now we will just make it work
 * with linux. Other operating systems appear to be much smarter than linux
 * anyway and have setproctitle(). We also won't bother saving the original
 * argv array, we shouldn't need it again.
 *
 * See:
 * postgresl-9.3.4/src/backend/utils/misc/ps_status.c
 * util-linux-2.24/lib/setproctitle.c
 *
 * Note:
 * Could maybe also use prctl(), but that only sets the name that top shows
 * by default and is limited to 16 characters (probably won't fit an ampname).
 */
void set_proc_name(char *testname) {
    char *end;
    int buflen;
    int i;
    char **argv;
    int argc;
    extern char **environ;

    Log(LOG_DEBUG, "Setting name of process %d to '%s: %s %s'", getpid(),
            PACKAGE, vars.ampname, testname);

    /*
     * We have as much space to use as there are contiguous arguments. Every
     * argument should be contiguous, but I guess it's possible that they
     * aren't?
     */
    argc = vars.argc;
    argv = vars.argv;
    end = argv[0] + strlen(argv[0]);
    for ( i = 1; i < argc; i++ ) {
        if ( end + 1 == argv[i] ) {
            end = argv[i] + strlen(argv[i]);
        } else {
            /* not contiguous, stop looking */
            break;
        }
    }

    /*
     * We can also take over any contiguous space used for environment
     * strings if they directly follow the arguments, later making a new
     * environment elsewhere.
     */
    if ( i == argc ) {
        char **env;

        for ( i = 0; environ[i] != NULL; i++ ) {
            if ( end + 1 == environ[i] ) {
                end = environ[i] + strlen(environ[i]);
            } else {
                /* not contiguous, but keep counting environment size */
            }
        }

        /* if we found space we want to use, make a new environment */
        env = (char **) malloc((i + 1) * sizeof(char *));
        for ( i = 0; environ[i] != NULL; i++ ) {
            env[i] = strdup(environ[i]);
        }
        /* null terminate the environment variable array */
        env[i] = NULL;

        /*
         * If we wanted to be really good we could keep a reference to
         * this so we can free it when the test ends, but it's going to
         * get freed anyway.
         */
        environ = env;
    }

    /* we can use as much space as we have contiguous memory */
    buflen = end - argv[0];

    /*
     * Null the rest of the arguments so we don't get pointers to random
     * parts of the new process name.
     */
    for ( i = 1; i < argc; i++ ) {
        argv[i] = NULL;
    }

    /* put our new name at the front of argv[0] and null the rest of it */
    snprintf(argv[0], buflen-1, "%s: %s %s", PACKAGE, vars.ampname, testname);
    memset(argv[0] + strlen(argv[0]) + 1, 0, buflen - strlen(argv[0]) - 1);

    Log(LOG_DEBUG, "Set name of process %d to '%s'", getpid(), argv[0]);
}



/*
 * Try to get the best timestamp that is available to us, in order of
 * preference: SO_TIMESTAMP, SIOCGSTAMP, gettimeofday().
 */
static void get_timestamp(int sock, struct msghdr *msg, struct timeval *now) {
    struct cmsghdr *c;
    struct timeval *tv;

    assert(msg);
    assert(now);

#ifdef SO_TIMESTAMP
    /* try getting the timestamp using SO_TIMESTAMP if available */
    for ( c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c) ) {
        if ( c->cmsg_level != SOL_SOCKET || c->cmsg_type != SO_TIMESTAMP ) {
            continue;
        }
        if ( c->cmsg_len < CMSG_LEN(sizeof(struct timeval)) ) {
            continue;
        }
        tv = ((struct timeval*)CMSG_DATA(c));
        now->tv_sec = tv->tv_sec;
        now->tv_usec = tv->tv_usec;
        return;
    }
#endif

    /* next try using SIOCGSTAMP to get a timestamp */
    if ( ioctl(sock, SIOCGSTAMP, now) < 0 ) {
        /* failing that, call gettimeofday() which we know will work */
        gettimeofday(now, NULL);
    }
}



/*
 * Given a pair of sockets (ipv4 and ipv6), wait for data to arrive on either
 * of them, up to maxwait microseconds. If data arrives before the timeout
 * then return which socket received the data, otherwise -1.
 */
int wait_for_data(struct socket_t *sockets, int *maxwait) {
    struct timeval start_time, end_time;
    struct timeval timeout;
    int delay;
    int max_fd;
    int ready;
    fd_set readset;

    assert(sockets);
    assert(sockets->socket || sockets->socket6);

    gettimeofday(&start_time, NULL);

    max_fd = -1;
    delay = 0;

    do {
	/*
	 * if there has been an error then update timeout by how long we have
	 * already taken so we can carry on where we left off
	 */
	if ( delay > *maxwait ) {
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 0;
	} else {
	    timeout.tv_sec = S_FROM_US(*maxwait - delay);
	    timeout.tv_usec = US_FROM_US(*maxwait - delay);
	}

	/* fd sets are undefined after an error, so set them every time too */
	FD_ZERO(&readset);
	if ( sockets->socket > 0 ) {
	    FD_SET(sockets->socket, &readset);
	    max_fd = sockets->socket;
	}

	if ( sockets->socket6 > 0 ) {
	    FD_SET(sockets->socket6, &readset);
	    if ( sockets->socket6 > max_fd ) {
		max_fd = sockets->socket6;
	    }
	}

	ready = select(max_fd+1, &readset, NULL, NULL, &timeout);

	/*
	 * we can't always trust the value of timeout after select returns, so
	 * check for ourselves how much time has elapsed
	 */
	gettimeofday(&end_time, NULL);
	delay = DIFF_TV_US(end_time, start_time);

	/* if delay is less than zero then maybe the clock was adjusted */
	if ( delay < 0 ) {
	    delay = 0;
	}

	/* continue until there is data to read or we get a non EINTR error */
    } while ( ready < 0 && errno == EINTR );

    /* remove the time waited so far from maxwait */
    *maxwait -= delay;
    if ( *maxwait < 0 ) {
	*maxwait = 0;
    }

    /* if there was a non-EINTR error then report it */
    if ( ready < 0 ) {
	Log(LOG_WARNING, "select() failed");
	return -1;
    }

    /* return the appropriate socket that has data waiting */
    if ( sockets->socket > 0 && FD_ISSET(sockets->socket, &readset) ) {
	return AF_INET;
    }

    if ( sockets->socket6 > 0 && FD_ISSET(sockets->socket6, &readset) ) {
	return AF_INET6;
    }

    return -1;
}



/*
 * Wait for up to timeout microseconds to receive a packet on the given
 * sockets and return the number of bytes read. If valid pointers with
 * storage for an address or timeval are given then they will be populated
 * with the source address and time the packet was received.
 */
int get_packet(struct socket_t *sockets, char *buf, int buflen,
        struct sockaddr *saddr, int *timeout, struct timeval *now) {

    int bytes;
    int sock;
    int family;
    socklen_t addrlen;
    struct iovec iov;
    struct msghdr msg;
    char ans_data[4096];

    assert(sockets);
    assert(sockets->socket || sockets->socket6);
    assert(timeout);

    /* wait for data to be ready, up to timeout (wait will update it) */
    if ( (family = wait_for_data(sockets, timeout)) <= 0 ) {
        return 0;
    }

    /* determine which socket we have received data on and read from it */
    switch ( family ) {
        case AF_INET: sock = sockets->socket;
                      addrlen = sizeof(struct sockaddr_in);
                      break;
        case AF_INET6: sock = sockets->socket6;
                       addrlen = sizeof(struct sockaddr_in6);
                       break;
        default: return 0;
    };

    /* set up the message structure, including the user supplied packet */
    iov.iov_base = buf;
    iov.iov_len = buflen;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = saddr;
    msg.msg_namelen = addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ans_data;
    msg.msg_controllen = sizeof(ans_data);

    /* receive the packet that we know is ready on one of our sockets */
    if ( (bytes = recvmsg(sock, &msg, 0)) < 0 ) {
        Log(LOG_ERR, "Failed to recvmsg()");
        exit(-1);
    }

    /* populate the timestamp argument with the receive time of packet */
    if ( now ) {
        get_timestamp(sock, &msg, now);
    }

    return bytes;
}



/*
 * Enforce a minimum inter-packet delay for test traffic. Try to send a packet
 * but if it is too soon for the test to be sending again then return a delay
 * time to wait (in microseconds).
 */
int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest,
        uint32_t inter_packet_delay, struct timeval *sent) {

    int bytes_sent;
    static struct timeval last = {0, 0};
    struct timeval now;
    int delay;

    assert(sock > 0);
    assert(size > 0);
    assert(packet);
    assert(dest);

    gettimeofday(&now, NULL);

    /* determine how much time is left to wait until the minimum delay */
    if ( last.tv_sec != 0 && DIFF_TV_US(now, last) < inter_packet_delay ) {
	delay = inter_packet_delay - DIFF_TV_US(now, last);
    } else {
	delay = 0;
	last.tv_sec = now.tv_sec;
	last.tv_usec = now.tv_usec;

        /* populate sent timestamp as well, if not null */
        if ( sent ) {
            sent->tv_sec = now.tv_sec;
            sent->tv_usec = now.tv_usec;
        }
    }

    /*
     * if there is still time to wait before the next packet then return
     * control to the caller, in case they want to do more work while waiting
     */
    if ( delay != 0 ) {
	return delay;
    }

    bytes_sent = sendto(sock, packet, size, 0, dest->ai_addr, dest->ai_addrlen);

    /* TODO determine error and/or send any unsent bytes */
    if ( bytes_sent != size ) {
        Log(LOG_DEBUG, "Only sent %d of %d bytes", bytes_sent, size);
        return -1;
    }

    return 0;
}



/*
 * Determine the name for a given address structure. Currently the name is
 * stored using the ai_canonname field in the struct addrinfo, which is
 * filled in when the structure is created (but not by getaddrinfo).
 */
char *address_to_name(struct addrinfo *address) {
    assert(address);
    assert(address->ai_canonname);
    return address->ai_canonname;
}



/*
 * Compare two addresses for equality. Returns an integer less than, equal to,
 * or greater than zero if address a is less than, equal to or greater than
 * address b, respectively.
 */
int compare_addresses(const struct sockaddr *a,
        const struct sockaddr *b, int len) {
    if ( a == NULL || b == NULL ) {
        return -1;
    }

    if ( a->sa_family != b->sa_family ) {
        return (a->sa_family > b->sa_family) ? 1 : -1;
    }

    /* all addresses match if no bits are checked */
    if ( len == 0 ) {
        return 0;
    }

    if ( a->sa_family == AF_INET ) {
        struct sockaddr_in *a4 = (struct sockaddr_in*)a;
        struct sockaddr_in *b4 = (struct sockaddr_in*)b;
        if ( len > 0 && len <= 32 ) {
            uint32_t mask = ntohl(0xffffffff << (32 - len));
            if ( (a4->sin_addr.s_addr & mask) ==
                    (b4->sin_addr.s_addr & mask) ) {
                return 0;
            }
            return ((a4->sin_addr.s_addr & mask) >
                    (b4->sin_addr.s_addr & mask)) ? 1 : -1;
        }
        return memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(struct in_addr));
    }

    if ( a->sa_family == AF_INET6 ) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6*)a;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6*)b;
        if ( len > 0 && len <= 128 ) {
            uint32_t mask[4];
            int i;
            for ( i = 0; i < 4; i++ ) {
                if ( len >= ((i + 1) * 32) ) {
                    mask[i] = 0xffffffff;
                } else if ( len < ((i + 1) * 32) && len > (i * 32) ) {
                    mask[i] = ntohl(0xffffffff << (((i + 1) * 32) - len));
                } else {
                    mask[i] = 0;
                }
            }

            for ( i = 0; i < 4; i++ ) {
                if ( (a6->sin6_addr.s6_addr32[i] & mask[i]) !=
                        (b6->sin6_addr.s6_addr32[i] & mask[i]) ) {
                    return ((a6->sin6_addr.s6_addr32[i] & mask[i]) >
                            (b6->sin6_addr.s6_addr32[i] & mask[i])) ? 1 : -1;
                }
            }
            return 0;
        }
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(struct in6_addr));
    }

    return -1;
}



/*
 *
 */
struct addrinfo *get_numeric_address(char *address, char *port) {
    struct addrinfo hints, *result;

    assert(address);

    Log(LOG_DEBUG, "Trying to get numeric host for %s", address);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    /* XXX do we need to set socktype or protocol? */

    /* check if the given string is one of our addresses */
    if ( getaddrinfo(address, port, &hints, &result) == 0 ) {
        return result;
    }

    return NULL;
}



/*
 * Bind a socket to a particular network device.
 */
int bind_socket_to_device(int sock, char *device) {
    assert(device);

    Log(LOG_DEBUG, "Trying to bind socket to device '%s'", device);

    if ( setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device,
                strlen(device)+1) < 0 ) {
        Log(LOG_WARNING, "Failed to bind to device %s: %s", device,
                strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Bind a socket to a particular address.
 */
int bind_socket_to_address(int sock, struct addrinfo *address) {
    char addrstr[INET6_ADDRSTRLEN];

    assert(address);
    assert(sock >= 0);

    Log(LOG_DEBUG, "Binding socket to source address %s",
            amp_inet_ntop(address, addrstr));

    if ( bind(sock, ((struct sockaddr*)address->ai_addr),
                address->ai_addrlen) < 0 ) {
        Log(LOG_DEBUG, "Failed to bind socket to address: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Bind all sockets in the test socket structure to a particular device.
 * Will only try to bind valid test sockets - if one of the IPv4 and IPv6
 * sockets isn't set then it will be ignored.
 */
int bind_sockets_to_device(struct socket_t *sockets, char *device) {
    Log(LOG_DEBUG, "Binding socket to interface %s", device);
    assert(sockets);
    assert(sockets->socket >= 0 || sockets->socket6 >= 0);
    assert(device);

    if ( sockets->socket >= 0 ) {
        if ( bind_socket_to_device(sockets->socket, device) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv4 socket to device %s", device);
            return -1;
        }
    }

    if ( sockets->socket6 >= 0 ) {
        if ( bind_socket_to_device(sockets->socket6, device) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv6 socket to device %s", device);
            return -1;
        }
    }

    return 0;
}



/*
 * Bind the sockets in the test socket structure to a particular source
 * address (one for IPv4 and one for IPv6 obviously). Will only try to bind
 * valid test sockets - if one of the IPv4 and IPv6 sockets isn't set or
 * there is no address set for that family then it will be ignored.
 */
int bind_sockets_to_address(struct socket_t *sockets,
        struct addrinfo *sourcev4, struct addrinfo *sourcev6) {
    char addrstr[INET6_ADDRSTRLEN];

    assert(sockets);
    assert( (sockets->socket >= 0 && sourcev4) ||
            (sockets->socket6 >= 0 && sourcev6) );

    if ( sourcev4 && sockets->socket >= 0 ) {
        Log(LOG_DEBUG, "Binding socket to source IPv4 address %s",
                amp_inet_ntop(sourcev4, addrstr));

        if ( bind_socket_to_address(sockets->socket, sourcev4) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv4 socket to address: %s",
                amp_inet_ntop(sourcev4, addrstr));
            return -1;
        }
    }

    if ( sourcev6 && sockets->socket6 >= 0 ) {
        Log(LOG_DEBUG, "Binding socket to source IPv6 address %s",
                amp_inet_ntop(sourcev6, addrstr));

        if ( bind_socket_to_address(sockets->socket6, sourcev6) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv6 socket to address: %s",
                amp_inet_ntop(sourcev6, addrstr));
            return -1;
        }
    }

    return 0;
}



/*
 * Enable socket timestamping if it is available.
 *
 * TODO should this whole function be contained within the ifdef as well as
 * the call? Or better to always call it but maybe do no work?
 */
static void set_timestamp_socket_option(int sock) {
    assert(sock >= 0);
#ifdef SO_TIMESTAMP
    int one = 1;
    /* try to enable socket timestamping using SO_TIMESTAMP */
    if ( setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one)) < 0 ) {
        Log(LOG_DEBUG, "No SO_TIMESTAMP support, using SIOCGSTAMP");
    }
#endif
}



/*
 * Set all the default options that our test sockets need to perform the tests.
 *
 * TODO return failure if anything important actually fails to be set? There
 * is currently nothing important enough to warn about.
 *
 * TODO can we make some sort of cross test open socket function that means
 * this can be called automagically? There is a lot of repetition in the
 * individual test open socket functions and device binding functions that
 * could be removed.
 */
int set_default_socket_options(struct socket_t *sockets) {
    assert(sockets);
    assert(sockets->socket >= 0 || sockets->socket6 >= 0);

    if ( sockets->socket >= 0 ) {
        set_timestamp_socket_option(sockets->socket);
    }

    if ( sockets->socket6 >= 0 ) {
        set_timestamp_socket_option(sockets->socket6);
    }

    return 0;
}



/*
 * TODO should this be part of the default socket options?
 */
int set_dscp_socket_options(struct socket_t *sockets, uint8_t dscp) {
    int value;

    assert(sockets);
    assert(sockets->socket > 0 || sockets->socket6 > 0);

    value = dscp;

    Log(LOG_DEBUG, "Setting DSCP value to %d\n", value);

    if ( sockets->socket > 0 ) {
        if ( setsockopt(sockets->socket, IPPROTO_IP, IP_TOS, &value,
                    sizeof(value)) < 0 ) {
            Log(LOG_WARNING, "Failed to set IPv4 DSCP to %d: %s", value,
                    strerror(errno));
            return -1;
        }
    }

    if ( sockets->socket6 > 0 ) {
        if ( setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_TCLASS, &value,
                    sizeof(value)) < 0 ) {
            Log(LOG_WARNING, "Failed to set IPv6 DSCP to %d: %s", value,
                    strerror(errno));
            return -1;
        }
    }

    return 0;
}



/*
 * Check if a given file exists, failure to exist is only an error if
 * the strict flag is set.
 */
int check_exists(char *path, int strict) {
    struct stat statbuf;
    int stat_result;

    stat_result = stat(path, &statbuf);

    /* error calling stat, report it and return and error */
    if ( stat_result < 0 && errno != ENOENT ) {
        Log(LOG_WARNING, "Failed to stat file %s: %s", path, strerror(errno));
        return -1;
    }

    /* file exists */
    if ( stat_result == 0 ) {
        /* check it's a normal file or a symbolic link */
        if ( S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode) ) {
            return 0;
        }

        Log(LOG_WARNING, "File %s exists, but is not a regular file", path);
        return -1;
    }

    /* file was manually specified, but doesn't exist, that's an error */
    if ( strict ) {
        Log(LOG_WARNING, "Manually specified file %s not found", path);
        return -1;
    }

    /* file doesn't exist, but that's ok as strict isn't set */
    return 1;
}



/*
 * Copy the address from a struct addrinfo into a protocol buffer byte field,
 * setting the length appropriately. Returns 1 if an address was successfully
 * copied.
 */
int copy_address_to_protobuf(ProtobufCBinaryData *dst,
        const struct addrinfo *src) {
    assert(dst);

    if ( src == NULL ) {
        dst->data = 0;
        dst->len = 0;
        return 0;
    }

    switch ( src->ai_family ) {
        case AF_INET:
            dst->data = (void*)&((struct sockaddr_in*)src->ai_addr)->sin_addr;
            dst->len = sizeof(struct in_addr);
            break;
        case AF_INET6:
            dst->data = (void*)&((struct sockaddr_in6*)src->ai_addr)->sin6_addr;
            dst->len = sizeof(struct in6_addr);
            break;
        default:
            Log(LOG_WARNING, "Unknown address family %d\n", src->ai_family);
            dst->data = NULL;
            dst->len = 0;
            break;
    };

    return dst->data ? 1 : 0;
}



/*
 *
 */
int parse_dscp_value(const char *value, uint8_t *result) {
    /* check if the name of a code point was given, if so set the right value */
    if ( strncasecmp(value, "cs0", strlen("cs0")) == 0 ||
            strncasecmp(value, "none", strlen("none")) == 0 ||
            strncasecmp(value, "default", strlen("default")) == 0 ) {
        *result = 0;
    } else if ( strncasecmp(value, "cs1", strlen("cs1")) == 0 ) {
        *result = 0b001000;
    } else if ( strncasecmp(value, "cs2", strlen("cs2")) == 0 ) {
        *result = 0b010000;
    } else if ( strncasecmp(value, "cs3", strlen("cs3")) == 0 ) {
        *result = 0b011000;
    } else if ( strncasecmp(value, "cs4", strlen("cs4")) == 0 ) {
        *result = 0b100000;
    } else if ( strncasecmp(value, "cs5", strlen("cs5")) == 0 ) {
        *result = 0b101000;
    } else if ( strncasecmp(value, "cs6", strlen("cs6")) == 0 ) {
        *result = 0b110000;
    } else if ( strncasecmp(value, "cs7", strlen("cs7")) == 0 ) {
        *result = 0b111000;
    } else if ( strncasecmp(value, "af11", strlen("af11")) == 0 ) {
        *result = 0b001010;
    } else if ( strncasecmp(value, "af12", strlen("af12")) == 0 ) {
        *result = 0b001100;
    } else if ( strncasecmp(value, "af13", strlen("af13")) == 0 ) {
        *result = 0b001110;
    } else if ( strncasecmp(value, "af21", strlen("af21")) == 0 ) {
        *result = 0b010010;
    } else if ( strncasecmp(value, "af22", strlen("af22")) == 0 ) {
        *result = 0b010100;
    } else if ( strncasecmp(value, "af23", strlen("af23")) == 0 ) {
        *result = 0b010110;
    } else if ( strncasecmp(value, "af31", strlen("af31")) == 0 ) {
        *result = 0b011010;
    } else if ( strncasecmp(value, "af32", strlen("af32")) == 0 ) {
        *result = 0b011100;
    } else if ( strncasecmp(value, "af33", strlen("af33")) == 0 ) {
        *result = 0b011110;
    } else if ( strncasecmp(value, "af41", strlen("af41")) == 0 ) {
        *result = 0b100010;
    } else if ( strncasecmp(value, "af42", strlen("af42")) == 0 ) {
        *result = 0b100100;
    } else if ( strncasecmp(value, "af43", strlen("af43")) == 0 ) {
        *result = 0b100110;
    } else if ( strncasecmp(value, "va", strlen("va")) == 0 ) {
        *result = 0b101100;
    } else if ( strncasecmp(value, "ef", strlen("ef")) == 0 ) {
        *result = 0b101110;
    } else {
        int converted;
        char *endptr;
        /* check if a binary value was given for the DSCP value */
        errno = 0;
        converted = strtol(value, &endptr, 2);
        if ( errno != 0 || *endptr != '\0' || converted >= (1 << 6) ) {
            /* if not, then try base 8, 10 and 16 */
            errno = 0;
            converted = strtol(value, &endptr, 0);
            if ( errno != 0 || *endptr != '\0' || converted >= (1 << 6) ) {
                *result = 0;
                return -1;
            }
        }
        *result = converted;
    }

    /* DSCP is only 6 bits long */
    *result = *result << 2;

    return 0;
}
