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
#include <fcntl.h>
#include <sys/stat.h>
#include <gnutls/x509.h>


char* certfile;
char* keyfile;

static gnutls_certificate_credentials_t cred;
static gnutls_certificate_credentials_t scred;
static gnutls_dh_params_t dhparams;
static gnutls_priority_t priorities;

static gnutls_x509_crt_t cacert;
static gnutls_x509_privkey_t cakey;
static gnutls_x509_crt_t starcert;
static gnutls_x509_privkey_t sessionkey;
static unsigned int serial = 0;

int verifycert(gnutls_session_t session);
int gencert(gnutls_session_t, const gnutls_datum_t* req_ca_rdn, int nreqs,
	const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length,
	gnutls_retr2_st *);

void gnutlsinit() {
	int bits;
	int rc;

	gnutls_global_init();
	
	rc = gnutls_priority_init(&priorities, "PERFORMANCE", NULL);
	if (rc < 0) {
		warn("[GnuTLS] Error initializing cipher priority.\n");
		exit(1);
	}
	
	gnutls_certificate_allocate_credentials(&cred);
	//gnutls_certificate_set_x509_trust_file(cred, "/etc/pki/tls/certs/ca-bundle.crt", GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_retrieve_function(cred, gencert);
	
	gnutls_certificate_allocate_credentials(&scred);
	gnutls_certificate_set_verify_function(scred, verifycert);
	
	bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW);
	gnutls_dh_params_init(&dhparams);
	log("[GnuTLS] Generating %d-bit DH parameters...\n", bits);
	gnutls_dh_params_generate2(dhparams, bits);

	gnutls_certificate_set_dh_params(cred, dhparams);
	
	gnutls_x509_privkey_init(&sessionkey);
	bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_RSA, GNUTLS_SEC_PARAM_LOW);
	log("[GnuTLS] Generating %d-bit session key...\n", bits);
	gnutls_x509_privkey_generate(sessionkey, GNUTLS_PK_RSA, bits, 0);
}

void gnutlspostinit() {
	int fd;
	struct stat st;
	int rc;
	gnutls_datum_t datum;
	gnutls_x509_crt_t* certs;

	if (!certfile || !keyfile) return;

	rc = stat(keyfile, &st);
	if (rc) {
		warn("[GnuTLS] Error fetching info about keyfile %s: %m\n", keyfile);
		return;
	}

	fd = open(keyfile, O_RDONLY, 0);
	if (!fd) {
		warn("[GnuTLS] Error opening keyfile %s: %m\n", keyfile);
		return;
	}
	datum.data = malloc(st.st_size+1);
	datum.size = st.st_size;
	rc = read(fd, datum.data, st.st_size);
	if (rc != st.st_size) {
		warn("[GnuTLS] Error reading keyfile %s: %m\n", keyfile);
		exit(1);
	}
	close(fd);
	datum.data[st.st_size] = 0;
	
	gnutls_x509_privkey_init(&cakey);
	rc = gnutls_x509_privkey_import(cakey, &datum, GNUTLS_X509_FMT_PEM);
	if (rc < 0) {
		warn("[GnuTLS] Error importing private key from %s: %s\n", keyfile, gnutls_strerror(rc));
		exit(1);
	}
	free(datum.data);


	
	rc = stat(certfile, &st);
	if (rc) {
		warn("[GnuTLS] Error fetching info about certfile %s: %m\n", certfile);
		exit(1);
	}

	fd = open(certfile, O_RDONLY, 0);
	if (!fd) {
		warn("[GnuTLS] Error opening certfile %s: %m\n", certfile);
		exit(1);
	}
	datum.data = malloc(st.st_size+1);
	datum.size = st.st_size;
	rc = read(fd, datum.data, st.st_size);
	if (rc != st.st_size) {
		warn("[GnuTLS] Error reading certfile %s: %m\n", certfile);
		exit(1);
	}
	close(fd);
	datum.data[st.st_size] = 0;
	
	gnutls_x509_crt_init(&cacert);
	rc = gnutls_x509_crt_import(cacert, &datum, GNUTLS_X509_FMT_PEM);
	if (rc < 0) {
		warn("[GnuTLS] Error importing certificate from %s: %s\n", certfile, gnutls_strerror(rc));
		exit(1);
	}
	free(datum.data);


	
	gnutls_x509_crt_print(cacert, GNUTLS_CRT_PRINT_ONELINE, &datum);
	log("[GnuTLS] Loaded cert: %s\n", datum.data);
	gnutls_free(datum.data);
	
	
	
	gnutls_x509_crt_init(&starcert);
	gnutls_x509_crt_set_dn_by_oid(starcert, GNUTLS_OID_X520_COMMON_NAME, 0, "*", 1);
	gnutls_x509_crt_set_serial(starcert, &serial, 4); serial++;
	gnutls_x509_crt_set_activation_time(starcert, time(NULL)-86400);
	gnutls_x509_crt_set_expiration_time(starcert, time(NULL)+86400*3650);
	gnutls_x509_crt_set_key(starcert, sessionkey);
	gnutls_x509_crt_set_key_usage(starcert, GNUTLS_KEY_DATA_ENCIPHERMENT|GNUTLS_KEY_KEY_ENCIPHERMENT);
	
	gnutls_x509_crt_sign(starcert, cacert, cakey);
	
	gnutls_x509_crt_print(starcert, GNUTLS_CRT_PRINT_ONELINE, &datum);
	log("[GnuTLS] Generated cert: %s\n", datum.data);
	gnutls_free(datum.data);

	certs = (gnutls_x509_crt_t*)gnutls_malloc(sizeof(gnutls_x509_crt_t*));
	certs[0] = starcert;

	rc = gnutls_certificate_set_x509_key(cred, certs, 1, sessionkey);
	if (rc < 0) {
		warn("[GnuTLS] Error setting certificate: %s\n", gnutls_strerror(rc));
		exit(1);
	}
}

int gnutlswriteall(gnutls_session_t fd, const char* buffer, int size) {
	int pos = 0;
	int rc;
	do {
		rc = gnutls_record_send(fd, buffer + pos, size - pos);
		if (rc <= 0) return rc;
		pos += rc;
	} while (pos < size);
	return size;
}

void* gnutlsthread(void* arg) {
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
	gnutls_session_t csession = NULL, ssession = NULL;
	char* firstpacket;
	int firstpacketsize;
	
	running++;
	buffer = (char*)malloc(BUFFERSIZE);
	
	rc = gnutls_init(&csession, GNUTLS_SERVER);
	if (rc) {
		warn("[%d] GnuTLS server init failed.\n", csock);
		goto end;
	}
	gnutls_credentials_set(csession, GNUTLS_CRD_CERTIFICATE, cred);
	gnutls_certificate_server_set_request(csession, GNUTLS_CERT_IGNORE);
	gnutls_priority_set(csession, priorities);
	
	gnutls_transport_set_ptr(csession, (gnutls_transport_ptr_t)(long)csock);
	
	do {
		rc = gnutls_handshake(csession);
	} while (rc < 0 && !gnutls_error_is_fatal(rc));
	if (rc < 0) {
		warn("[%d] Fatal error during GnuTLS handshake with client: %s\n", csock, gnutls_strerror(rc));
		goto end;
	}

	/* Find connection info from client. This *should* all fit in the first packet. */
	rc = gnutls_record_recv(csession, buffer, BUFFERSIZE);
	if (rc == 0) {
		warn("[%d] Client closed connection before sending headers.\n", csock);
		goto end;
	}
	if (rc < 0) {
		warn("[%d] Error reading request headers: %s\n", csock, gnutls_strerror(rc));
		goto end;
	}
	firstpacket = (char*)malloc(rc);
	memcpy(firstpacket, buffer, rc);
	firstpacketsize = rc;

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
		if (!directconnect(csock, ssock, host, 443, map)) goto end;
		break;

	case SOCKS4:
		rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
		if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
		if (!socks4connect(csock, ssock, host, 443)) goto end;
		break;
	
	case SOCKS4A:
		rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
		if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
		if (!socks4aconnect(csock, ssock, host, 443)) goto end;
		break;
	
	case SOCKS5:
		rc = connect(ssock, (struct sockaddr*)&addr, sizeof(addr));
		if (rc) { warn("[%d] Could not connect to server: %m\n", csock); return 0; }
		if (!socks5connect(csock, ssock, host, 443)) goto end;
		break;
	}

	/* We're connected through the proxy, now start SSL to the end server. */
	rc = gnutls_init(&ssession, GNUTLS_CLIENT);
	if (rc) {
		warn("[%d] GnuTLS client init failed.\n", csock);
		goto end;
	}
	gnutls_credentials_set(ssession, GNUTLS_CRD_CERTIFICATE, scred);
	gnutls_transport_set_ptr(ssession, (gnutls_transport_ptr_t)(long)ssock);
	gnutls_server_name_set(ssession, GNUTLS_NAME_DNS, host, strlen(host));
	gnutls_priority_set(ssession, priorities);
	
	do {
		rc = gnutls_handshake(ssession);
	} while (rc < 0 && !gnutls_error_is_fatal(rc));
	if (rc < 0) {
		warn("[%d] Fatal error during GnuTLS handshake with server: %s\n", csock, gnutls_strerror(rc));
		goto end;
	}
	
	rc = gnutlswriteall(ssession, firstpacket, firstpacketsize);
	free(firstpacket); 
	
	
	/* Relay data. */
	FD_ZERO(&fds);
	FD_SET(csock, &fds);
	FD_SET(ssock, &fds);
	
	do {
		rfds = fds;
		rc = select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
		if (rc < 0) break;
		
		if (FD_ISSET(csock, &rfds)) {
			rc = gnutls_record_recv(csession, buffer, BUFFERSIZE);
			if (rc == 0) break;
			if (rc < 0) {
				warn("[%d] Error reading from client: %m\n", csock);
				break;
			}
		
			rc = gnutlswriteall(ssession, buffer, rc);
			if (rc <= 0) {
				warn("[%d] Error sending to server: %m\n", csock);
				break;
			}
		}
		if (FD_ISSET(ssock, &rfds)) {
			rc = gnutls_record_recv(ssession, buffer, BUFFERSIZE);
			if (rc == 0) break;
			if (rc <= 0) {
				warn("[%d] Error reading from server: %m\n", csock);
				break;
			}
		
			rc = gnutlswriteall(csession, buffer, rc);
			if (rc <= 0) {
				warn("[%d] Error sending to client: %m\n", csock);
				break;
			}
		}
	} while (exitflag == 0);
	
	end:
	if (ssession) {
		gnutls_bye(ssession, GNUTLS_SHUT_RDWR);
		gnutls_deinit(ssession);
	}
	if (csession) {
		gnutls_deinit(csession);	
		gnutls_bye(csession, GNUTLS_SHUT_RDWR);
	}
	if (csock > 0) close(csock);
	if (ssock > 0) close(ssock);
	if (host) free(host);
	if (buffer) free(buffer);
	running--;
	log("[%d] SSL relay finished.\n", csock);
	return NULL;
}

int verifycert(gnutls_session_t session) {
	return 0;
}

int gencert(gnutls_session_t session, 
	const gnutls_datum_t* req_ca_rdn, int nreqs,
	const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length,
	gnutls_retr2_st* ret)
{
	char hostname[256];
	size_t hostlen = 256;
	unsigned int hosttype;
	int rc;
	gnutls_datum_t datum;
	gnutls_x509_crt_t cert;
	gnutls_x509_privkey_t key;
	
	rc = gnutls_server_name_get(session, hostname, &hostlen, &hosttype, 0);
	if (rc < 0) {
		warn("[GnuTLS] Error retrieving server name during certificate generation: %s\n", strerror(rc));
		ret->cert_type = GNUTLS_CRT_X509;
		ret->key_type = GNUTLS_PRIVKEY_X509;
		ret->cert.x509 = (gnutls_x509_crt_t*)malloc(sizeof(gnutls_x509_crt_t*));
		ret->cert.x509[0] = starcert;
		ret->ncerts = 1;
		ret->key.x509 = sessionkey;
		ret->deinit_all = 0;
		return 0;
	}
	
	gnutls_x509_privkey_init(&key);
	gnutls_x509_privkey_cpy(key, sessionkey);
	
	gnutls_x509_crt_init(&cert);
	gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, hostname, hostlen);
	gnutls_x509_crt_set_serial(cert, &serial, 4); serial++;
	gnutls_x509_crt_set_activation_time(cert, time(NULL)-86400);
	gnutls_x509_crt_set_expiration_time(cert, time(NULL)+86400);
	gnutls_x509_crt_set_key(cert, key);
	gnutls_x509_crt_set_key_usage(cert, GNUTLS_KEY_DATA_ENCIPHERMENT|GNUTLS_KEY_KEY_ENCIPHERMENT);
	
	gnutls_x509_crt_sign(cert, cacert, cakey);
	
	gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_ONELINE, &datum);
	log("[GnuTLS] Generated cert: %s\n", datum.data);
	gnutls_free(datum.data);
	
	ret->cert_type = GNUTLS_CRT_X509;
	ret->key_type = GNUTLS_PRIVKEY_X509;
	ret->cert.x509 = (gnutls_x509_crt_t*)malloc(sizeof(gnutls_x509_crt_t*));
	ret->cert.x509[0] = cert;
	ret->ncerts = 1;
	ret->key.x509 = key;
	ret->deinit_all = 1;
	
	return 0;
}



/* EOF */

