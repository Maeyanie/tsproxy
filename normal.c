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

int writeall(int fd, const char* buffer, int size) {
	int pos = 0;
	int rc;
	do {
		rc = write(fd, buffer + pos, size - pos);
		if (rc <= 0) return rc;
		pos += rc;
	} while (pos < size);
	return size;
}

void* connthread(void* arg) {
	const struct Mapping* map;
	struct sockaddr_in addr;
	int ssock = 0;
	int csock = (long)arg;
	char* buffer;
	int rc;
	char* tok;
	char* host = NULL;
	fd_set fds;
	fd_set rfds;
	int tries = 0;
	
	running++;
	buffer = (char*)malloc(BUFFERSIZE);

	do {
		rc = recv(csock, buffer, BUFFERSIZE-1, MSG_PEEK);
		if (rc == 0) {
			warn("[%d] Client closed connection before sending headers.\n", csock);
			goto end;
		}
		if (rc < 0) {
			warn("[%d] Error reading request headers: %m\n", csock);
			goto end;
		}
		buffer[rc] = 0;
		if (!strstr(buffer, "Host: ")) {
			usleep(10000);
			tries++;
			if (tries > 1000) goto end;
			continue;
		}
	} while (0);

	buffer[rc] = 0;
	strtok(buffer, "\r\n");
	/* First token should be "GET /foo HTTP/1.1" so we can skip that safely. */
	while ((tok = strtok(NULL, "\r\n"))) {
		if (!strncasecmp(tok, "Host: ", 6)) {
			host = strdup(tok + 6);
			break;
		}
	}
	
	if (host == NULL) {
		warn("[%d] Client did not provide Host: header.\n", csock);
		goto end;
	}
	


	/* Establish SOCKS connection. */
	map = findserver(host);
	
	ssock = socket(AF_INET, SOCK_STREAM, 0);

	switch (map->proto) {
	case INVALID:
		goto end;
	
	case DIRECT:
		if (!directconnect(csock, ssock, host, "80", map)) goto end;
		break;
		
	case SOCKS4:
		rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
		if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
		if (!socks4connect(csock, ssock, host, 80)) goto end;
		break;
	
	case SOCKS4A:
		rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
		if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
		if (!socks4aconnect(csock, ssock, host, 80)) goto end;
		break;
	
	case SOCKS5:
		rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
		if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
		if (!socks5connect(csock, ssock, host, 80)) goto end;
		break;
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



/* EOF */

