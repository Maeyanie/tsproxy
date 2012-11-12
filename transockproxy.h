/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License only.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <signal.h>

#ifdef GNUTLS
#include <gnutls/gnutls.h>
#endif

/* This must be at least enough to hold HTTP headers. */
#define BUFFERSIZE 8192

enum Proto {
	DIRECT,
	SOCKS4,
	SOCKS4A,
	SOCKS5
};

struct Mapping {
	const char* pattern;
	struct sockaddr_in proxy;
	enum Proto proto;
};

extern volatile sig_atomic_t exitflag;
extern volatile sig_atomic_t running;
extern enum Proto defproto;
extern struct sockaddr_in defaddr;
extern struct Mapping** mappings;
extern int mappingcount;

#ifdef GNUTLS
extern char* certfile;
extern char* keyfile;
#endif


void gnutlsinit();
void gnutlspostinit();

void readconfig(struct sockaddr_in* laddr, struct sockaddr_in* ssladdr);
void* connthread(void* arg);
void* gnutlsthread(void* arg);
int writeall(int fd, const char* buffer, int size);
void sighandle(int sig);
void findserver(enum Proto* proto, struct sockaddr_in* addr, const char* host);

int directconnect(int csock, int ssock, char* host, unsigned short defport);
int socks4connect(int csock, int ssock, char* host, unsigned short defport);
int socks4aconnect(int csock, int ssock, char* host, unsigned short defport);
int socks5connect(int csock, int ssock, char* host, unsigned short defport);

#ifdef DAEMON
#define log(a...)
#define warn(a...)
#else
#define log(a...) printf(a)
#define warn(a...) fprintf(stderr, a)
#endif

