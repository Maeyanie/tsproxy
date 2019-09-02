all: transockproxy transockproxys transockproxyd

transockproxy: transockproxy.c normal.c
	$(CC) -g -Wall -o $@ $^ -lpthread

transockproxyd: transockproxy.c normal.c
	$(CC) -g -Wall -DDAEMON -o $@ $^ -lpthread

transockproxys: transockproxy.c normal.c gnutls.c
	$(CC) -g -Wall -DGNUTLS -o $@ $^ -lpthread -lgnutls

transockproxysd: transockproxy.c normal.c gnutls.c
	$(CC) -g -Wall -DDAEMON -DGNUTLS -o $@ $^ -lpthread -lgnutls

