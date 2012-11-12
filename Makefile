all: transockproxy transockproxys transockproxyd

transockproxy: transockproxy.c normal.c
	$(CC) -m32 -g -Wall -Werror -o $@ $< normal.c -lpthread

transockproxys: transockproxy.c normal.c gnutls.c
	$(CC) -g -Wall -Werror -DGNUTLS -o $@ $< normal.c gnutls.c -lpthread -lgnutls

transockproxyd: transockproxy.c normal.c
	$(CC) -m32 -g -Wall -Werror -DDAEMON -o $@ $< normal.c -lpthread
