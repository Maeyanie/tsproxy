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

#include "transockproxy.h"

volatile sig_atomic_t exitflag = 0;
volatile sig_atomic_t running = 0;
enum Proto defproto;
struct sockaddr_in defaddr;
struct Mapping** mappings;
int mappingcount;

static const unsigned char socks4a[] = {
	0x04, 0x01,
	0x00, 0x50, /* Replace this with port if it's not 80. */
	0x00, 0x00, 0x00, 0x01,
	0x00
	};

static const unsigned char socks5a[] = {
	0x05, 0x01, 0x00
	};
static const unsigned char socks5b[] = {
	0x05, 0x01, 
	0x00, 0x03
	};

int main(int argc, char* argv[]) {
	int rc;
	struct sockaddr_in laddr;
	struct sockaddr_in ssladdr;
	struct sockaddr_in caddr;
	unsigned int caddrsize;
	int lsock = 0, csock, sslsock = 0;
	pthread_t tid;
	pthread_attr_t tattr;
	fd_set fds;
	fd_set rfds;
	
	#ifdef GNUTLS
	gnutlsinit();
	#endif

	readconfig(&laddr, &ssladdr);
	
	#ifdef GNUTLS
	gnutlspostinit();
	#endif
	
	siginterrupt(SIGINT, 1);
	siginterrupt(SIGTERM, 1);
	signal(SIGINT, sighandle);
	signal(SIGTERM, sighandle);
	
	if (laddr.sin_port) {
		lsock = socket(AF_INET, SOCK_STREAM, 0);
		if (!lsock) { perror("Could not open listen socket"); return 2; }
	
		rc = 1;
		setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
	
		rc = bind(lsock, (struct sockaddr*)&laddr, sizeof(laddr));
		if (rc) { perror("Could not bind to port"); return 2; }
	
		listen(lsock, 32);
	}
	
	#if defined(GNUTLS) || defined(OPENSSL)
	if (ssladdr.sin_port) {
		sslsock = socket(AF_INET, SOCK_STREAM, 0);
		if (!sslsock) { perror("Could not open SSL socket"); return 2; }
	
		rc = 1;
		setsockopt(sslsock, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
	
		rc = bind(sslsock, (struct sockaddr*)&ssladdr, sizeof(ssladdr));
		if (rc) { perror("Could not bind to SSL port"); return 2; }
	
		listen(sslsock, 32);
	}
	#endif
	
	pthread_attr_init(&tattr);
	/*For some reason I'm getting undefined reference on this?
	pthread_attr_setdetatchstate(&tattr, PTHREAD_CREATE_DETACHED);*/
	rc = pthread_attr_setstacksize(&tattr, PTHREAD_STACK_MIN);
	if (rc) fprintf(stderr, "Could not set thread stacksize, using default.\n");
	
	printf("Ready.\n");
	#ifdef DAEMON
	daemon(0, 0);
	#endif

	FD_ZERO(&fds);
	if (lsock) FD_SET(lsock, &fds);
	if (sslsock) FD_SET(sslsock, &fds);

	while (exitflag == 0) {
		caddrsize = sizeof(caddr);
		
		rfds = fds;
		rc = select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
		if (rc < 0) { log("select() returned %d: %m\n", rc); break; }
		
		if (FD_ISSET(lsock, &rfds)) {
			csock = accept(lsock, (struct sockaddr*)&caddr, &caddrsize);
			if (csock <= 0) {
				log("accept() returned %d: %m\n", csock);
				break;
			}
		
			log("[%d] New connection from %s:%hu\n", 
				csock, inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
		
			pthread_create(&tid, NULL, connthread, (void*)(long)csock);
			pthread_detach(tid);
		}
		#ifdef GNUTLS
		if (FD_ISSET(sslsock, &rfds)) {
			csock = accept(sslsock, (struct sockaddr*)&caddr, &caddrsize);
			if (csock <= 0) {
				log("accept() returned %d: %m\n", csock);
				break;
			}
		
			log("[%d] New SSL connection from %s:%hu\n", 
				csock, inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
		
			pthread_create(&tid, NULL, gnutlsthread, (void*)(long)csock);
			pthread_detach(tid);		
		}
		#endif
	}
	
	if (lsock) close(lsock);
	if (sslsock) close(sslsock);
	
	log("Waiting for all threads to exit.\n");
	while (running > 0 && exitflag == 1) {
		log("Waiting... %d thread%s left.\n", running, running == 1 ? "" : "s");
		sleep(1);
	}
	
	#ifdef GNUTLS
	gnutls_global_deinit();
	#endif
	
	log("Exiting.\n");
	return 0;
}


void readconfig(struct sockaddr_in* laddr, struct sockaddr_in* ssladdr) {
	struct hostent* hostinfo;
	char* proto;
	char* host;
	int port;
	char* line = NULL;
	size_t linelen = 0;
	char* tok;
	struct Mapping* map;
	
	laddr->sin_family = AF_INET;
	laddr->sin_addr.s_addr = htonl(INADDR_ANY);
	laddr->sin_port = 0;
	
	ssladdr->sin_family = AF_INET;
	ssladdr->sin_addr.s_addr = htonl(INADDR_ANY);
	ssladdr->sin_port = 0;

	defaddr.sin_family = AF_INET;
	defaddr.sin_port = 0;
	
	FILE* fp = fopen("transockproxy.conf", "r");
	if (!fp) { fprintf(stderr, "Error opening transockproxy.conf: %m\n"); exit(1); }	

	while (getline(&line, &linelen, fp) > 0) {
		if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') continue;
		tok = strtok(line, " ");
		
		if (!strcmp(tok, "listen")) {
			tok = strtok(NULL, "\r\n");
			port = atoi(tok);
			laddr->sin_port = htons(port);
			printf("Listening on port %d.\n", port);
		} else if (!strcmp(tok, "default")) {
			proto = strtok(NULL, ":\r\n");
			host = strtok(NULL, ":")+2;
			tok = strtok(NULL, "\r\n");
			port = tok ? atoi(tok) : 0;
			
			if (!strcmp(proto, "direct")) {
				defproto = DIRECT;
				defaddr.sin_port = -1;
				printf("Default server: direct\n");
				continue;
			} else if (!strcmp(proto, "socks4")) {
				defproto = SOCKS4;
			} else if (!strcmp(proto, "socks4a")) {
				defproto = SOCKS4A;
			} else if (!strcmp(proto, "socks5")) {
				defproto = SOCKS5;
			} else {
				fprintf(stderr, "Unrecognized protocol '%s' (must be direct, socks4, socks4a, or socks5)\n", proto);
				exit(1);
			}
			
			hostinfo = gethostbyname(host);
			if (!hostinfo) { fprintf(stderr, "Unknown host %s\n", host); exit(1); }

			defaddr.sin_addr = *(struct in_addr*)hostinfo->h_addr;
			defaddr.sin_port = htons(port);

			printf("Default server: %s://%s:%hu\n", proto, host, port);
		} else if (!strcmp(tok, "map")) {
			map = (struct Mapping*)malloc(sizeof(struct Mapping));
			map->pattern = strdup(strtok(NULL, " "));
			
			proto = strtok(NULL, ":\r\n");
			if (!strcmp(proto, "direct")) {
				map->proto = DIRECT;
				printf("Mapping pattern %s to direct\n", map->pattern);
				continue;
			} else if (!strcmp(proto, "socks4")) {
				map->proto = SOCKS4;
			} else if (!strcmp(proto, "socks4a")) {
				map->proto = SOCKS4A;
			} else if (!strcmp(proto, "socks5")) {
				map->proto = SOCKS5;
			} else {
				fprintf(stderr, "Unrecognized protocol '%s' (must be direct, socks4, socks4a, or socks5)\n", proto);
				exit(1);
			}

			host = strtok(NULL, ":")+2;
			hostinfo = gethostbyname(host);
			if (!hostinfo) { fprintf(stderr, "Unknown host %s\n", host); exit(1); }
			
			tok = strtok(NULL, "\r\n");
			port = atoi(tok);
			
			map->proxy.sin_family = AF_INET;
			map->proxy.sin_addr = *(struct in_addr*)hostinfo->h_addr;
			map->proxy.sin_port = htons(port);
			
			mappings = (struct Mapping**)realloc(mappings, (mappingcount+1) * sizeof(struct Mapping*));
			mappings[mappingcount] = map;
			mappingcount++;

			printf("Mapping pattern %s to %s://%s:%hu\n", map->pattern, proto, host, port);
		}
		#if defined(GNUTLS) || defined(OPENSSL)
		else if (!strcmp(tok, "ssl")) {
			tok = strtok(NULL, "\r\n");
			port = atoi(tok);
			ssladdr->sin_port = htons(port);
			printf("Listening on SSL port %d.\n", port);
		} else if (!strcmp(tok, "sslcert")) {
			tok = strtok(NULL, "\r\n");
			certfile = strdup(tok);
		} else if (!strcmp(tok, "sslkey")) {
			tok = strtok(NULL, "\r\n");
			keyfile = strdup(tok);
		}
		#endif
	}
	
	fclose(fp);
	
	#ifdef GNUTLS
	if (ssladdr->sin_port) {
		if (certfile == NULL || keyfile == NULL) {
			fprintf(stderr, "Error loading config: SSL requested but missing sslcert and/or sslkey entries.\n");
			exit(1);
		}
		/*if (gnutls_certificate_set_x509_key_file(cred, certfile, keyfile, GNUTLS_X509_FMT_PEM) < 0) {
			fprintf(stderr, "Error loading SSL cert or key file.\n");
			exit(1);
		}*/
	}
	#endif
	
	if (laddr->sin_port == 0 && ssladdr->sin_port == 0) {
		fprintf(stderr, "Error loading config: Not listening on any ports. Needs a 'listen' and/or 'ssl' line.\n");
		exit(1);
	}
	if (defaddr.sin_port == 0) {
		fprintf(stderr, "Error loading config: No 'default' line found.\n");
		exit(1);
	}
}


void findserver(enum Proto* proto, struct sockaddr_in* addr, const char* host) {
	int x;
	for (x = 0; x < mappingcount; x++) {
		if (!fnmatch(mappings[x]->pattern, host, 0)) {
			*proto = mappings[x]->proto;
			if (mappings[x]->proto != DIRECT)
				memcpy(addr, &(mappings[x]->proxy), sizeof(struct sockaddr_in));
			return;
		}
	}
	*proto = defproto;
	memcpy(addr, &defaddr, sizeof(struct sockaddr_in));
}

int directconnect(int csock, int ssock, char* host, unsigned short defport) {
	struct sockaddr_in addr;
	struct hostent* hostinfo;
	char* portstr;
	int rc;

	log("[%d] Establishing direct connection to %s.\n", csock, host);
	
	addr.sin_family = AF_INET;

	host = strtok(host, ":");
	hostinfo = gethostbyname(host);
	if (hostinfo == NULL) {
		warn("[%d] Could not resolve host %s.\n", csock, host);
		return 0;
	}
	addr.sin_addr = *(struct in_addr*)hostinfo->h_addr;
	
	portstr = strtok(NULL, "\r\n");
	if (portstr != NULL) {
		addr.sin_port = htons(atoi(portstr));
	} else {
		addr.sin_port = htons(defport);
	}
	
	rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
	if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
	
	return 1;
}

int socks4connect(int csock, int ssock, char* host, unsigned short defport) {
	char buffer[1024];
	struct hostent* hostinfo;
	char* portstr;
	short port;

	log("[%d] Establishing SOCKS4 proxy connection to %s.\n", csock, host);
	memcpy(buffer, socks4a, sizeof(socks4a));

	host = strtok(host, ":");
	hostinfo = gethostbyname(host);
	if (hostinfo == NULL) {
		warn("[%d] Could not resolve host %s.\n", csock, host);
		return 0;
	}
	memcpy(buffer + 4, hostinfo->h_addr, 4);
	
	portstr = strtok(NULL, "\r\n");
	if (portstr != NULL) {
		port = htons(atoi(portstr));
	} else {
		port = htons(defport);
	}
	memcpy(buffer + 2, &port, 2);

	write(ssock, buffer, sizeof(socks4a));

	read(ssock, buffer, 8);
	if (buffer[1] != 0x5a) {
		warn("[%d] SOCKS proxy rejected request.\n", csock);
		return 0;
	}
	return 1;
}

int socks4aconnect(int csock, int ssock, char* host, unsigned short defport) {
	char buffer[1024];
	char* portstr;
	short port;

	log("[%d] Establishing SOCKS4a proxy connection to %s.\n", csock, host);
	memcpy(buffer, socks4a, sizeof(socks4a));

	host = strtok(host, ":");
	portstr = strtok(NULL, "\r\n");
	if (portstr != NULL) {
		port = htons(atoi(portstr));
	} else {
		port = htons(defport);
	}
	memcpy(buffer + 2, &port, 2);

	strcpy(buffer + sizeof(socks4a), host);
	write(ssock, buffer, sizeof(socks4a) + strlen(host) + 1);

	read(ssock, buffer, 8);
	if (buffer[1] != 0x5a) {
		warn("[%d] SOCKS proxy rejected request.\n", csock);
		return 0;
	}
	return 1;
}

int socks5connect(int csock, int ssock, char* host, unsigned short defport) {
	char buffer[1024];
	char* portstr;
	short port;
	int rc;
	int pos;
	/*int x;*/

	log("[%d] Establishing SOCKS5 proxy connection to %s.\n", csock, host);
	
	write(ssock, socks5a, sizeof(socks5a));
	rc = read(ssock, buffer, 2);
	
	if (rc != 2 || buffer[0] != 0x05 || buffer[1] == 0xFF) {
		warn("[%d] SOCKS5 proxy requires authentication, this is unsupported.\n", csock);
		return 0;
	}

	memcpy(buffer, socks5b, sizeof(socks5b));

	host = strtok(host, ":");
	buffer[sizeof(socks5b)] = (unsigned char)strlen(host);
	memcpy(buffer + sizeof(socks5b) + 1, host, strlen(host));

	portstr = strtok(NULL, "\r\n");
	if (portstr != NULL) {
		port = htons(atoi(portstr));
	} else {
		port = htons(defport);
	}
	memcpy(buffer + sizeof(socks5b) + 1 + strlen(host), &port, 2);
	
	write(ssock, buffer, sizeof(socks5b) + strlen(host) + 3);
	rc = read(ssock, buffer, 4);
	pos = rc;
	if (rc != 4 || buffer[1] != 0) {
		warn("[%d] SOCKS5 proxy rejected request, code %hhu.\n", csock, buffer[1]);
	}
	switch (buffer[3]) {
	case 1: // IPv4 address
		rc = read(ssock, buffer + 4, 6);
		pos += rc;
		if (rc != 6) { warn("[%d] Expected 6 bytes, got %d, during handshake.\n", csock, rc); return 0; }
		break;
	case 3: // Domain name
		rc = read(ssock, buffer + 4, 1);
		pos += rc;
		if (rc != 1) { warn("[%d] Expected 1 byte, got %d, during handshake.\n", csock, rc); return 0; }

		rc = read(ssock, buffer + 5, buffer[4]+2);
		pos += rc;
		if (rc != 6) { warn("[%d] Expected %d bytes, got %d, during handshake.\n", csock, buffer[4]+2, rc); return 0; }
		break;
	case 4: // IPv6 address
		rc = read(ssock, buffer + 4, 18);
		pos += rc;
		if (rc != 6) { warn("[%d] Expected 18 bytes, got %d, during handshake.\n", csock, rc); return 0; }
		break;
	default:
		warn("[%d] SOCKS5 response address is unexpected type %hhu.\n", csock, buffer[3]);
		return 0;
	}
	
	/*log("[%d] socks5:", csock);
	for (x = 0; x < pos; x++) {
		log(" %hhx", buffer[x]);
	}
	log("\n");*/
	
	return 1;
}	

void sighandle(int sig) {
	exitflag++;
}



/* EOF */

