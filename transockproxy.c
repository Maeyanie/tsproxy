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
    
/* 
 *  To compile:
 *  gcc -O2 -o transockproxy transockproxy.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <signal.h>

/* This must be at least enough to hold HTTP headers. */
#define BUFFERSIZE 8192

static volatile sig_atomic_t exitflag = 0;
static volatile sig_atomic_t running = 0;
static struct sockaddr_in saddr;

static const unsigned char socks4a[] = {
	0x04, 0x01,
	0x00, 0x50, /* Hardcoded at port 80. Should really check for port in Host: header. */
	0x00, 0x00, 0x00, 0x01,
	0x00
	};


void* connthread(void* arg);
int writeall(int fd, char* buffer, int size);
void sighandle(int sig);

#ifdef DAEMON
#define log(a...)
#define warn(a...)
#else
#define log(a...) printf(a)
#define warn(a...) fprintf(stderr, a)
#endif

int main(int argc, char* argv[]) {
	int rc;
	struct hostent* hostinfo;
	struct sockaddr_in laddr;
	struct sockaddr_in caddr;
	unsigned int caddrsize;
	int lport, sport;
	int lsock, csock;
	pthread_t tid;
	pthread_attr_t tattr;

	if (argc != 4) {
		printf("Usage: %s <listen port> <socks server> <socks port>\n", argv[0]);
		printf("Example: %s 80 10.0.0.1 1080\n", argv[0]);
		return 1;
	}
	
	signal(SIGINT, sighandle);
	signal(SIGTERM, sighandle);
	
	lport = atoi(argv[1]);
	sport = atoi(argv[3]);
	
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_ANY);
	laddr.sin_port = htons(lport);
	
	hostinfo = gethostbyname(argv[2]);
	if (!hostinfo) { fprintf(stderr, "Unknown host %s\n", argv[2]); return 2; }
	
	saddr.sin_family = AF_INET;
	saddr.sin_addr = *(struct in_addr*)hostinfo->h_addr;
	saddr.sin_port = htons(sport);
	
	lsock = socket(AF_INET, SOCK_STREAM, 0);
	if (!lsock) { perror("Could not open listen socket"); return 2; }
	
	rc = bind(lsock, (struct sockaddr*)&laddr, sizeof(saddr));
	if (rc) { perror("Could not bind to port"); return 2; }
	
	listen(lsock, 32);
	
	pthread_attr_init(&tattr);
	/*For some reason I'm getting undefined reference on this?
	pthread_attr_setdetatchstate(&tattr, PTHREAD_CREATE_DETACHED);*/
	rc = pthread_attr_setstacksize(&tattr, PTHREAD_STACK_MIN);
	if (rc) fprintf(stderr, "Could not set thread stacksize, using default.\n");
	
	printf("Ready.\n");
	#ifdef DAEMON
	daemon(0, 0);
	#endif

	while (exitflag == 0) {	
		caddrsize = sizeof(caddr);
		
		csock = accept(lsock, (struct sockaddr*)&caddr, &caddrsize);
		if (csock <= 0) break;
		
		log("[%d] New connection from %s:%hu\n", 
			csock, inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
		
		pthread_create(&tid, NULL, connthread, (void*)csock);
		pthread_detach(tid);
	}
	
	close(lsock);
	
	log("Waiting for all threads to exit.\n");
	while (running > 0) {
		log("Waiting... %d thread%s left.\n", running, running == 1 ? "" : "s");
		sleep(1);
	}
	
	return 0;
}


void* connthread(void* arg) {
	int ssock = 0;
	int csock = (int)arg;
	char* buffer;
	int rc;
	char* tok;
	char* host = NULL;
	fd_set fds;
	fd_set rfds;
	
	running++;
	buffer = (char*)malloc(BUFFERSIZE);

	/* Find connection info from client. This *should* all fit in the first packet. */
	rc = recv(csock, buffer, BUFFERSIZE, MSG_PEEK);
	if (rc == 0) {
		warn("[%d] Client closed connection before sending headers.\n", csock);
		goto end;
	}
	if (rc < 0) {
		warn("[%d] Error reading request headers: %m\n", csock);
		goto end;
	}

	buffer[rc] = 0;
	tok = strtok(buffer, "\r\n");
	do {
		if (!strncasecmp(tok, "Host: ", 6)) {
			host = strdup(tok + 6);
			break;
		}
	} while ((tok = strtok(NULL, "\r\n")));
	
	if (host == NULL) {
		warn("[%d] Client did not provide Host: header.\n", csock);
		goto end;
	}


	/* Establish SOCKS connection. */
	ssock = socket(AF_INET, SOCK_STREAM, 0);
	rc = connect(ssock, (struct sockaddr*)&saddr, sizeof(saddr));
	if (rc < 0) {
		warn("[%d] Could not connect to server: %m\n", csock);
		goto end;
	}
	
	log("[%d] Establishing proxy connection to %s.\n", csock, host);
	memcpy(buffer, socks4a, sizeof(socks4a));
	strcpy(buffer + sizeof(socks4a), host);
	write(ssock, buffer, sizeof(socks4a) + strlen(host) + 1);
	
	read(ssock, buffer, 8);
	if (buffer[1] != 0x5a) {
		warn("[%d] SOCKS proxy rejected request.\n", csock);
		goto end;
	}
	
	
	/* Relay data. */
	FD_ZERO(&fds);
	FD_SET(csock, &fds);
	FD_SET(ssock, &fds);
	
	do {
		rfds = fds;
		rc = select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
		if (rc < 0) break;
		
		if (FD_ISSET(csock, &rfds)) {
			rc = read(csock, buffer, BUFFERSIZE);
			if (rc == 0) break;
			if (rc < 0) {
				warn("[%d] Error reading from client: %m\n", csock);
				break;
			}
		
			rc = writeall(ssock, buffer, rc);
			if (rc <= 0) {
				warn("[%d] Error sending to server: %m\n", csock);
				break;
			}
		}
		if (FD_ISSET(ssock, &rfds)) {
			rc = read(ssock, buffer, BUFFERSIZE);
			if (rc == 0) break;
			if (rc <= 0) {
				warn("[%d] Error reading from server: %m\n", csock);
				break;
			}
		
			rc = writeall(csock, buffer, rc);
			if (rc <= 0) {
				warn("[%d] Error sending to client: %m\n", csock);
				break;
			}
		}
	} while (exitflag == 0);
	
	end:
	if (csock > 0) close(csock);
	if (ssock > 0) close(ssock);
	if (host) free(host);
	if (buffer) free(buffer);
	running--;
	log("[%d] Relay finished.\n", csock);
	return NULL;
}


void sighandle(int sig) {
	exitflag = 1;
}


int writeall(int fd, char* buffer, int size) {
	int pos = 0;
	int rc;
	do {
		rc = write(fd, buffer + pos, size - pos);
		if (rc <= 0) return rc;
		pos += rc;
	} while (pos < size);
	return size;
}



/* EOF */

