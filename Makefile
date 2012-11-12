all: transockproxy transockproxys transockproxyd

transockproxy: transockproxy.c normal.c
	$(CC) -g -Wall -Werror -o $@ $^ -lpthread

transockproxys: transockproxy.c normal.c gnutls.c
	$(CC) -g -Wall -Werror -DGNUTLS -o $@ $^ -lpthread -lgnutls

transockproxyd: transockproxy.c normal.c
	$(CC) -g -Wall -Werror -DDAEMON -o $@ $^ -lpthread
