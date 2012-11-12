all: transockproxy transockproxys transockproxyd

transockproxy: transockproxy.c normal.c
	$(CC) -g -Wall -Werror -o $@ $^ -lpthread

transockproxyd: transockproxy.c normal.c
	$(CC) -g -Wall -Werror -DDAEMON -o $@ $^ -lpthread

transockproxys: transockproxy.c normal.c gnutls.c
	$(CC) -g -Wall -Werror -DGNUTLS -o $@ $^ -lpthread -lgnutls

transockproxysd: transockproxy.c normal.c gnutls.c
	$(CC) -g -Wall -Werror -DDAEMON -DGNUTLS -o $@ $^ -lpthread -lgnutls

