#ifndef GLOBALS_H
#define GLOBALS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

struct listen {
	int port;
	in_addr addr;
	int iface;
};

extern struct listen control;
extern struct listen relay;

#endif /* GLOBALS_H */
